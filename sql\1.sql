CREATE TABLE user_payment_status (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `uuid` varchar(45) DEFAULT NULL,
  `user_uuid` varchar(45) DEFAULT NULL,
  `allowed_trial_days` int(10) DEFAULT NULL,
  `trial_expired` int(4) DEFAULT 0,
  `payment_done` int(4) DEFAULT 0,
  `stripe_customer_id` varchar(1000) DEFAULT NULL,
  `email` varchar(255) DEFAULT NULL,
  `session_id` VARCHAR(45) NULL DEFAULT NULL,
  `stripe_subscription_id` varchar(1000) DEFAULT NULL,
  `subscription_status` varchar(100) DEFAULT NULL,
  `subscription_status_updated_timestamp` int(10) DEFAULT NULL,
  `trial_start_timestamp` int(10) DEFAULT NULL,
  `subscription_start_timestamp` int(10) DEFAULT NULL,
  `next_payment_timestamp` int(10) DEFAULT NULL,
  `plan` VARCHAR(45) NULL DEFAULT NULL,
  `plan_type` VARCHAR(45) NULL DEFAULT NULL,
  `created_timestamp` int(10) DEFAULT NULL,
  `updated_timestamp` int(10) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

ALTER TABLE `user_payment_status`  ADD COLUMN `payment_method_session_id` varchar(1000) DEFAULT NULL;
ALTER TABLE `user_payment_status`  ADD COLUMN `payment_method_data` text DEFAULT NULL;
ALTER TABLE `user_payment_status`  ADD COLUMN `banner_manually_closed` int(4) DEFAULT 0;