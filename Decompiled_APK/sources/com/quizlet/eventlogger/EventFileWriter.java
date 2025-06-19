package com.quizlet.eventlogger;

import android.content.Context;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Date;
import java.util.logging.FileHandler;
import java.util.logging.Level;
import java.util.logging.LogRecord;

/* loaded from: classes2.dex */
public class EventFileWriter implements EventLogCounter {
    private static final String HOLDING_FILE_NAME_PREFIX = "/quizlet-event-rolled-log";
    private static final String LOG_FILE_NAME_PATTERN = "/quizlet-event-log-%g.txt";
    private static final String LOG_FILE_NAME_PREFIX = "/quizlet-event-log";
    public int a = 0;
    private final a mFileFormatter = new a();

    public static void b(Context context) throws IOException {
        String str = context.getFilesDir().getPath() + "/quizlet-event-log-0.txt";
        File file = new File(str);
        if (file.exists()) {
            StringBuilder sb = new StringBuilder();
            sb.append(context.getFilesDir().getPath());
            sb.append("/quizlet-event-rolled-log-" + new Date().getTime() + ".txt");
            if (!file.renameTo(new File(sb.toString()))) {
                throw new IOException("Failed to rename current file to rolled file");
            }
            FileOutputStream fileOutputStream = new FileOutputStream(str, false);
            try {
                fileOutputStream.write("".getBytes());
            } finally {
                fileOutputStream.flush();
                fileOutputStream.close();
            }
        }
    }

    @Override // com.quizlet.eventlogger.EventLogCounter
    public final synchronized int a() {
        return this.a;
    }

    public final void c(Context context, String str) throws Throwable {
        FileHandler fileHandler;
        FileHandler fileHandler2 = null;
        try {
            try {
                fileHandler = new FileHandler(context.getFilesDir().getPath() + LOG_FILE_NAME_PATTERN, 20480, 20, true);
            } catch (Exception e) {
                e = e;
            }
        } catch (Throwable th) {
            th = th;
        }
        try {
            fileHandler.setFormatter(this.mFileFormatter);
            fileHandler.publish(new LogRecord(Level.INFO, str));
            synchronized (this) {
                this.a++;
            }
            fileHandler.close();
        } catch (Exception e2) {
            e = e2;
            fileHandler2 = fileHandler;
            timber.log.c.a(e);
            if (fileHandler2 != null) {
                fileHandler2.close();
            }
        } catch (Throwable th2) {
            th = th2;
            fileHandler2 = fileHandler;
            if (fileHandler2 != null) {
                fileHandler2.close();
            }
            throw th;
        }
    }
}
