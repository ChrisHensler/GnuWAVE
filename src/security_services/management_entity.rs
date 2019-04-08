
use super::super::DataTypes::*;
use super::access_points;

pub struct StationSecurityManagementEntity {
  t:String,
}

pub fn new() -> (StationSecurityManagementEntity) {
  StationSecurityManagementEntity {
    t: String::from("Hello there!"),
  }
}
