package com.j256.ormlite.stmt.mapped;

import com.j256.ormlite.dao.Dao;
import com.j256.ormlite.dao.ObjectCache;
import com.j256.ormlite.field.FieldType;
import com.j256.ormlite.stmt.GenericRowMapper;
import com.j256.ormlite.support.DatabaseResults;
import com.j256.ormlite.table.TableInfo;
import java.lang.reflect.InvocationTargetException;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.Map;

/* loaded from: classes2.dex */
public abstract class BaseMappedQuery<T, ID> extends BaseMappedStatement<T, ID> implements GenericRowMapper<T> {
    private Map<String, Integer> columnPositions;
    private Object parent;
    private Object parentId;
    protected final FieldType[] resultsFieldTypes;

    public BaseMappedQuery(Dao<T, ID> dao, TableInfo<T, ID> tableInfo, String str, FieldType[] fieldTypeArr, FieldType[] fieldTypeArr2) {
        super(dao, tableInfo, str, fieldTypeArr);
        this.columnPositions = null;
        this.parent = null;
        this.parentId = null;
        this.resultsFieldTypes = fieldTypeArr2;
    }

    /* JADX WARN: Multi-variable type inference failed */
    @Override // com.j256.ormlite.stmt.GenericRowMapper
    public T mapRow(DatabaseResults databaseResults) throws SQLException, IllegalAccessException, IllegalArgumentException, InvocationTargetException {
        Object objBuildForeignCollection;
        ID id;
        Map<String, Integer> map = this.columnPositions;
        if (map == null) {
            map = new HashMap<>();
        }
        ObjectCache objectCacheForRetrieve = databaseResults.getObjectCacheForRetrieve();
        if (objectCacheForRetrieve != 0) {
            T t = (T) objectCacheForRetrieve.get(this.clazz, this.idField.resultToJava(databaseResults, map));
            if (t != null) {
                return t;
            }
        }
        T tCreateObjectInstance = this.dao.createObjectInstance();
        ID id2 = null;
        boolean z = false;
        for (FieldType fieldType : this.resultsFieldTypes) {
            if (fieldType.isForeignCollection()) {
                z = true;
            } else {
                Object objResultToJava = fieldType.resultToJava(databaseResults, map);
                if (objResultToJava == 0 || this.parent == null || fieldType.getField().getType() != this.parent.getClass() || !objResultToJava.equals(this.parentId)) {
                    id = objResultToJava;
                    fieldType.assignField(this.connectionSource, tCreateObjectInstance, id, false, objectCacheForRetrieve);
                } else {
                    fieldType.assignField(this.connectionSource, tCreateObjectInstance, this.parent, true, objectCacheForRetrieve);
                    id = objResultToJava;
                }
                if (fieldType.isId()) {
                    id2 = id;
                }
            }
        }
        if (z) {
            for (FieldType fieldType2 : this.resultsFieldTypes) {
                if (fieldType2.isForeignCollection() && (objBuildForeignCollection = fieldType2.buildForeignCollection(tCreateObjectInstance, id2)) != null) {
                    fieldType2.assignField(this.connectionSource, tCreateObjectInstance, objBuildForeignCollection, false, objectCacheForRetrieve);
                }
            }
        }
        ObjectCache objectCacheForStore = databaseResults.getObjectCacheForStore();
        if (objectCacheForStore != null && id2 != null) {
            objectCacheForStore.put(this.clazz, id2, tCreateObjectInstance);
        }
        if (this.columnPositions == null) {
            this.columnPositions = map;
        }
        return tCreateObjectInstance;
    }

    public void setParentInformation(Object obj, Object obj2) {
        this.parent = obj;
        this.parentId = obj2;
    }
}
