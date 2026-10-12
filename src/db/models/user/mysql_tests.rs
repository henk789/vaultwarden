use super::User;
use crate::db::{
    DbConnInner,
    models::Device,
    schema::{devices, users},
};
use diesel::{connection::SimpleConnection, mysql::MysqlConnection, prelude::*};

struct Database {
    admin: MysqlConnection,
    name: String,
    url: String,
}
impl Database {
    fn new() -> Self {
        let raw =
            std::env::var("VW_ACCOUNT_TEST_MYSQL_URL").expect("disposable MySQL gate required; see tests/README.md");
        let mut url = url::Url::parse(&raw).unwrap();
        assert_eq!(url.scheme(), "mysql");
        assert_eq!(url.username(), "root");
        assert_eq!(url.password(), Some("synthetic-account-test"));
        assert!(url.host_str().is_some_and(|host| host.parse::<std::net::IpAddr>().is_ok_and(|ip| ip.is_loopback())));
        assert_eq!(url.path(), "/mysql");
        assert!(url.query().is_none() && url.fragment().is_none());
        let mut admin = MysqlConnection::establish(&raw).unwrap();
        let name = format!("vw_account_{}", uuid::Uuid::new_v4().simple());
        admin.batch_execute(&format!("CREATE DATABASE {name};")).unwrap();
        url.set_path(&format!("/{name}"));
        let fixture = Self {
            admin,
            name,
            url: url.to_string(),
        };
        crate::db::mysql_migrations::run_migrations(&fixture.url).unwrap();
        fixture
    }
}
impl Drop for Database {
    fn drop(&mut self) {
        assert!(
            self.name.starts_with("vw_account_") && self.name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        );
        drop(self.admin.batch_execute(&format!("DROP DATABASE {};", self.name)));
    }
}

#[test]
#[ignore = "requires a disposable MySQL instance; see tests/README.md"]
fn mysql_nested_snapshot_cannot_hide_account_changes_or_new_sessions_from_revocation() {
    let db = Database::new();
    let mut reader = DbConnInner::Mysql(MysqlConnection::establish(&db.url).unwrap());
    let mut writer = DbConnInner::Mysql(MysqlConnection::establish(&db.url).unwrap());
    let user = uuid::Uuid::new_v4().to_string();
    let device = uuid::Uuid::new_v4().to_string();
    reader.batch_execute(&format!("INSERT INTO users (uuid,enabled,created_at,updated_at,login_verify_count,email,name,password_hash,salt,password_iterations,akey,private_key,security_stamp,equivalent_domains,excluded_globals,client_kdf_type,client_kdf_iter) VALUES ('{user}',1,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,0,'user@example.test','Synthetic user',UNHEX('00'),UNHEX(REPEAT('00',64)),100000,'old-wrapper','old-private-wrapper','old-stamp','[]','[]',0,600000);")).unwrap();
    reader.batch_execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ; BEGIN;").unwrap();
    let expected = users::table.first::<User>(&mut reader).unwrap();
    assert_eq!(devices::table.count().get_result::<i64>(&mut reader).unwrap(), 0);

    // Another grant commits after the outer transaction has established its
    // consistent-read view, before its nested account update takes the lock.
    writer.batch_execute(&format!("UPDATE users SET security_stamp='new-stamp',akey='new-wrapper' WHERE uuid='{user}'; INSERT INTO devices (uuid,user_uuid,created_at,updated_at,name,atype,refresh_token,twofactor_remember,push_uuid) VALUES ('{device}','{user}',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,'Synthetic device',14,'fresh-session-token','remembered-token','preserved-push-uuid');")).unwrap();
    reader.batch_execute("SAVEPOINT nested_guard; UPDATE users SET uuid=uuid;").unwrap();
    assert_eq!(users::table.first::<User>(&mut reader).unwrap().security_stamp, "old-stamp");
    assert_eq!(devices::table.count().get_result::<i64>(&mut reader).unwrap(), 0);

    let current = User::find_by_uuid_locked(&expected.uuid, &mut reader).unwrap();
    assert_eq!(current.security_stamp, "new-stamp");
    assert_eq!(current.akey, "new-wrapper");
    assert!(expected.lock_authentication_epoch(&mut reader).is_err());
    // The same locking-read rule must include the newly committed device even
    // though it is absent from the outer transaction's old SELECT snapshot.
    User::revoke_device_tokens(&expected.uuid, &mut reader).unwrap();
    reader.batch_execute("RELEASE SAVEPOINT nested_guard; COMMIT;").unwrap();
    let saved = devices::table.first::<Device>(&mut writer).unwrap();
    assert_ne!(saved.refresh_token, "fresh-session-token");
    assert!(saved.twofactor_remember.is_none());
    assert_eq!(saved.push_uuid.as_ref().map(|id| id.0.as_str()), Some("preserved-push-uuid"));
}
