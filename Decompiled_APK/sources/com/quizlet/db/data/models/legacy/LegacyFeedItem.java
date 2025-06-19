package com.quizlet.db.data.models.legacy;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.j256.ormlite.field.DatabaseField;
import com.j256.ormlite.table.DatabaseTable;

@JsonIgnoreProperties(ignoreUnknown = true)
@DatabaseTable(tableName = "feed_item")
/* loaded from: classes2.dex */
public abstract class LegacyFeedItem extends LegacyBaseDBModel {
    private static final String PK_FIELD = "pk";

    @DatabaseField
    private String dataClass;

    @DatabaseField
    private Long dataId;

    @DatabaseField
    private String feedUrl;

    @DatabaseField
    private boolean hidden;

    @DatabaseField
    private String originFeed;

    @DatabaseField(columnName = PK_FIELD, id = true)
    private String pk;

    @DatabaseField
    private String setIdsString;

    @DatabaseField
    private int timestamp;
}
