package androidx.compose.ui.node;

import android.content.res.TypedArray;
import android.media.MediaDrm;
import android.media.MediaMetadataRetriever;
import androidx.compose.runtime.C0814p;
import androidx.fragment.app.AbstractC1136h0;
import androidx.fragment.app.C1121a;
import androidx.fragment.app.Fragment;
import androidx.glance.appwidget.C1187o0;
import androidx.glance.appwidget.C1215s;
import androidx.glance.appwidget.C1219w;
import androidx.glance.appwidget.C1220x;
import androidx.glance.appwidget.D0;
import androidx.glance.appwidget.K0;
import androidx.recyclerview.widget.RecyclerView;
import java.util.HashMap;
import java.util.Locale;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.ForkJoinPool;
import java.util.concurrent.TimeUnit;
import kotlin.Pair;
import kotlin.jvm.internal.C4950i;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public abstract /* synthetic */ class B {
    public static int a(androidx.glance.unit.i iVar, int i, int i2) {
        return (Integer.hashCode(iVar.a) + i) * i2;
    }

    public static C1121a b(AbstractC1136h0 abstractC1136h0, AbstractC1136h0 abstractC1136h02) {
        abstractC1136h0.getClass();
        return new C1121a(abstractC1136h02);
    }

    public static String c(RecyclerView recyclerView, StringBuilder sb) {
        sb.append(recyclerView.D());
        return sb.toString();
    }

    public static String d(Class cls, String str) {
        return str + cls;
    }

    public static String e(Object obj, String str) {
        return str + obj;
    }

    public static String f(String str) {
        String string = UUID.randomUUID().toString();
        Intrinsics.checkNotNullExpressionValue(string, str);
        return string;
    }

    public static String g(String str, Fragment fragment, String str2) {
        return str + fragment + str2;
    }

    public static String h(String str, String str2, char c) {
        return str + str2 + c;
    }

    public static String i(String str, String str2, String str3, String str4) {
        return str + str2 + str3 + str4;
    }

    public static String j(StringBuilder sb, String str, String str2, String str3, String str4) {
        sb.append(str);
        sb.append(str2);
        sb.append(str3);
        sb.append(str4);
        return sb.toString();
    }

    public static String k(Locale locale, String str, String str2, Locale locale2, String str3) {
        Intrinsics.checkNotNullExpressionValue(locale, str);
        String lowerCase = str2.toLowerCase(locale2);
        Intrinsics.checkNotNullExpressionValue(lowerCase, str3);
        return lowerCase;
    }

    public static StringBuilder l(int i, String str) {
        StringBuilder sb = new StringBuilder(i);
        sb.append(str);
        return sb;
    }

    public static Pair m(int i, int i2, Integer num) {
        return new Pair(new K0(i, i2), num);
    }

    public static Pair n(int i, C1215s c1215s) {
        return new Pair(c1215s, new C1187o0(i));
    }

    public static Pair o(int i, C1220x c1220x) {
        return new Pair(c1220x, new C1219w(i));
    }

    public static Pair p(int i, D0 d0) {
        return new Pair(d0, new C1187o0(i));
    }

    public static C4950i q(org.koin.core.scope.a aVar, String str, org.koin.core.parameter.a aVar2, String str2, Class cls) {
        Intrinsics.checkNotNullParameter(aVar, str);
        Intrinsics.checkNotNullParameter(aVar2, str2);
        return kotlin.jvm.internal.K.a(cls);
    }

    public static void r(int i, HashMap map, String str, int i2, String str2) {
        map.put(str, Integer.valueOf(i));
        map.put(str2, Integer.valueOf(i2));
    }

    public static void s(C0814p c0814p, boolean z, boolean z2, boolean z3) {
        c0814p.p(z);
        c0814p.p(z2);
        c0814p.p(z3);
    }

    public static /* synthetic */ void t(AutoCloseable autoCloseable) throws Exception {
        boolean zIsTerminated;
        if (autoCloseable instanceof AutoCloseable) {
            autoCloseable.close();
            return;
        }
        if (!(autoCloseable instanceof ExecutorService)) {
            if (autoCloseable instanceof TypedArray) {
                ((TypedArray) autoCloseable).recycle();
                return;
            } else if (autoCloseable instanceof MediaMetadataRetriever) {
                ((MediaMetadataRetriever) autoCloseable).release();
                return;
            } else {
                if (!(autoCloseable instanceof MediaDrm)) {
                    throw new IllegalArgumentException();
                }
                ((MediaDrm) autoCloseable).release();
                return;
            }
        }
        ExecutorService executorService = (ExecutorService) autoCloseable;
        if (executorService == ForkJoinPool.commonPool() || (zIsTerminated = executorService.isTerminated())) {
            return;
        }
        executorService.shutdown();
        boolean z = false;
        while (!zIsTerminated) {
            try {
                zIsTerminated = executorService.awaitTermination(1L, TimeUnit.DAYS);
            } catch (InterruptedException unused) {
                if (!z) {
                    executorService.shutdownNow();
                    z = true;
                }
            }
        }
        if (z) {
            Thread.currentThread().interrupt();
        }
    }

    public static void u(StringBuilder sb, String str, String str2, String str3, String str4) {
        sb.append(str);
        sb.append(str2);
        sb.append(str3);
        sb.append(str4);
    }

    public static /* synthetic */ String v(int i) {
        switch (i) {
            case 1:
                return "NONE";
            case 2:
                return "LEFT";
            case 3:
                return "TOP";
            case 4:
                return "RIGHT";
            case 5:
                return "BOTTOM";
            case 6:
                return "BASELINE";
            case 7:
                return "CENTER";
            case 8:
                return "CENTER_X";
            case 9:
                return "CENTER_Y";
            default:
                throw null;
        }
    }

    public static /* synthetic */ String w(int i) {
        return i != 1 ? i != 2 ? i != 3 ? i != 4 ? i != 5 ? "null" : "Idle" : "LookaheadLayingOut" : "LayingOut" : "LookaheadMeasuring" : "Measuring";
    }

    public static /* synthetic */ String x(int i) {
        return i != 1 ? i != 2 ? i != 3 ? i != 4 ? "null" : "MatchParent" : "Expand" : "Fixed" : "Wrap";
    }
}
