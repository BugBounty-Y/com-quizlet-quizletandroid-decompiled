package com.quizlet.eventlogger;

import java.util.logging.Formatter;
import java.util.logging.LogRecord;

/* loaded from: classes2.dex */
public final class a extends Formatter {
    @Override // java.util.logging.Formatter
    public final String format(LogRecord logRecord) {
        return (logRecord == null || logRecord.getMessage() == null || logRecord.getMessage().length() == 0) ? "" : android.support.v4.media.session.a.k(logRecord.getMessage().replaceAll("\n", ""), "\n");
    }
}
