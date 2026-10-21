package com.vistay.authentication.domain;

public enum AccountType {
    CUSTOMER("customer_accounts"),
    ADMIN("admin_accounts"),
    HOST("host_accounts");

    private final String tableName;

    AccountType(String tableName) {
        this.tableName = tableName;
    }

    public String tableName() {
        return tableName;
    }
}
