package com.snowplowanalytics.core.tracker;

import androidx.camera.camera2.internal.AbstractC0147y;
import java.util.Arrays;
import java.util.HashMap;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public abstract class e {
    public static int a;
    public static com.snowplowanalytics.snowplow.tracker.c b = new com.quizlet.quizletandroid.ui.folder.logging.a(5);

    public static final void a(String tag, String msg, Object... args) {
        Intrinsics.checkNotNullParameter(tag, "tag");
        Intrinsics.checkNotNullParameter(msg, "msg");
        Intrinsics.checkNotNullParameter(args, "args");
        if (a >= 2) {
            b.a(AbstractC0147y.d("SnowplowTracker->", tag), c(msg, Arrays.copyOf(args, args.length)));
        }
    }

    public static final void b(String tag, String msg, Object... args) {
        Intrinsics.checkNotNullParameter(tag, "tag");
        Intrinsics.checkNotNullParameter(msg, "msg");
        Intrinsics.checkNotNullParameter(args, "args");
        if (a >= 1) {
            b.b(AbstractC0147y.d("SnowplowTracker->", tag), c(msg, Arrays.copyOf(args, args.length)));
        }
    }

    public static String c(String str, Object... objArr) {
        StringBuilder sb = new StringBuilder();
        String name = Thread.currentThread().getName();
        Intrinsics.checkNotNullExpressionValue(name, "currentThread().name");
        sb.append(name);
        sb.append('|');
        Object[] objArrCopyOf = Arrays.copyOf(objArr, objArr.length);
        String str2 = String.format(str, Arrays.copyOf(objArrCopyOf, objArrCopyOf.length));
        Intrinsics.checkNotNullExpressionValue(str2, "format(format, *args)");
        sb.append(str2);
        return sb.toString();
    }

    public static final void d(String tag, String msg, Object... args) {
        Throwable th;
        Intrinsics.checkNotNullParameter(tag, "tag");
        Intrinsics.checkNotNullParameter(msg, "msg");
        Intrinsics.checkNotNullParameter(args, "args");
        b(tag, msg, Arrays.copyOf(args, args.length));
        try {
            int length = args.length;
            int i = 0;
            while (true) {
                th = null;
                if (i >= length) {
                    break;
                }
                Object obj = args[i];
                if (!Throwable.class.isInstance(obj)) {
                    i++;
                } else if (obj instanceof Throwable) {
                    th = (Throwable) obj;
                }
            }
            com.snowplowanalytics.snowplow.event.g gVar = new com.snowplowanalytics.snowplow.event.g(tag, c(msg, Arrays.copyOf(args, args.length)), th);
            HashMap map = new HashMap();
            map.put("event", gVar);
            com.snowplowanalytics.core.utils.c.b(map, "SnowplowTrackerDiagnostic");
        } catch (Exception e) {
            Intrinsics.checkNotNullExpressionValue("e", "TAG");
            e("e", "Error logger can't report the error: " + e, new Object[0]);
        }
    }

    public static final void e(String tag, String msg, Object... args) {
        Intrinsics.checkNotNullParameter(tag, "tag");
        Intrinsics.checkNotNullParameter(msg, "msg");
        Intrinsics.checkNotNullParameter(args, "args");
        if (a >= 3) {
            b.d(AbstractC0147y.d("SnowplowTracker->", tag), c(msg, Arrays.copyOf(args, args.length)));
        }
    }
}
