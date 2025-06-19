package com.j256.ormlite.stmt;

import com.j256.ormlite.stmt.StatementBuilder;
import com.j256.ormlite.support.CompiledStatement;
import com.j256.ormlite.support.DatabaseConnection;
import com.j256.ormlite.support.DatabaseResults;
import java.sql.SQLException;

/* loaded from: classes2.dex */
public interface PreparedStmt<T> extends GenericRowMapper<T> {
    CompiledStatement compile(DatabaseConnection databaseConnection, StatementBuilder.StatementType statementType) throws SQLException;

    CompiledStatement compile(DatabaseConnection databaseConnection, StatementBuilder.StatementType statementType, int i) throws SQLException;

    int getNumArgs();

    String getStatement() throws SQLException;

    StatementBuilder.StatementType getType();

    @Override // com.j256.ormlite.stmt.GenericRowMapper
    /* synthetic */ Object mapRow(DatabaseResults databaseResults) throws SQLException;

    void setArgumentHolderValue(int i, Object obj) throws SQLException;
}
