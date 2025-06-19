package io.reactivex.rxjava3.internal.util;

import androidx.compose.animation.d0;
import com.google.android.gms.internal.ads.C2245jv;
import java.util.concurrent.TimeUnit;

/* loaded from: classes3.dex */
public abstract class c {
    public static final C2245jv a = new C2245jv("No further exceptions", 1);

    public static NullPointerException a(String str) {
        return new NullPointerException(str.concat(" Null values are generally not allowed in 3.x operators and sources."));
    }

    public static void b(Object obj, String str) {
        if (obj == null) {
            throw a(str);
        }
    }

    public static String c(long j, TimeUnit timeUnit) {
        StringBuilder sbT = d0.t(j, "The source did not signal an event for ", " ");
        sbT.append(timeUnit.toString().toLowerCase());
        sbT.append(" and has been terminated.");
        return sbT.toString();
    }

    public static RuntimeException d(Throwable th) {
        if (th instanceof Error) {
            throw ((Error) th);
        }
        return th instanceof RuntimeException ? (RuntimeException) th : new RuntimeException(th);
    }
}
