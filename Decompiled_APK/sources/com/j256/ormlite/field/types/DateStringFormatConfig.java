package com.j256.ormlite.field.types;

import java.text.DateFormat;
import java.text.SimpleDateFormat;

/* loaded from: classes2.dex */
public class DateStringFormatConfig {
    private final DateFormat dateFormat;
    private final String dateFormatStr;

    public DateStringFormatConfig(String str) {
        this.dateFormatStr = str;
        this.dateFormat = new SimpleDateFormat(str);
    }

    public DateFormat getDateFormat() {
        return (DateFormat) this.dateFormat.clone();
    }

    public String toString() {
        return this.dateFormatStr;
    }
}
