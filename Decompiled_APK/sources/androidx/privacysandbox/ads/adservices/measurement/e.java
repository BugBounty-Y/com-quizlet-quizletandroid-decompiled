package androidx.privacysandbox.ads.adservices.measurement;

import android.adservices.measurement.MeasurementManager;
import android.net.Uri;
import android.view.InputEvent;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C5028l;
import kotlinx.coroutines.E;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes.dex */
public abstract class e {
    public final MeasurementManager a;

    public e(MeasurementManager mMeasurementManager) {
        Intrinsics.checkNotNullParameter(mMeasurementManager, "mMeasurementManager");
        this.a = mMeasurementManager;
    }

    public static Object b(e eVar, a aVar, kotlin.coroutines.h<? super Unit> hVar) {
        new C5028l(1, kotlin.coroutines.intrinsics.h.b(hVar)).r();
        MeasurementManager measurementManager = eVar.a;
        throw null;
    }

    public static Object d(e eVar, kotlin.coroutines.h<? super Integer> frame) {
        C5028l c5028l = new C5028l(1, kotlin.coroutines.intrinsics.h.b(frame));
        c5028l.r();
        eVar.a.getMeasurementApiStatus(new androidx.arch.core.executor.a(1), new androidx.core.os.c(c5028l));
        Object objQ = c5028l.q();
        if (objQ == kotlin.coroutines.intrinsics.a.a) {
            Intrinsics.checkNotNullParameter(frame, "frame");
        }
        return objQ;
    }

    public static Object g(e eVar, Uri uri, InputEvent inputEvent, kotlin.coroutines.h<? super Unit> frame) {
        C5028l c5028l = new C5028l(1, kotlin.coroutines.intrinsics.h.b(frame));
        c5028l.r();
        eVar.a.registerSource(uri, inputEvent, new androidx.arch.core.executor.a(1), new androidx.core.os.c(c5028l));
        Object objQ = c5028l.q();
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        if (objQ == aVar) {
            Intrinsics.checkNotNullParameter(frame, "frame");
        }
        return objQ == aVar ? objQ : Unit.a;
    }

    public static Object h(e eVar, f fVar, kotlin.coroutines.h<? super Unit> hVar) {
        Object objM = E.m(new d(eVar, null), hVar);
        return objM == kotlin.coroutines.intrinsics.a.a ? objM : Unit.a;
    }

    public static Object j(e eVar, Uri uri, kotlin.coroutines.h<? super Unit> frame) {
        C5028l c5028l = new C5028l(1, kotlin.coroutines.intrinsics.h.b(frame));
        c5028l.r();
        eVar.a.registerTrigger(uri, new androidx.arch.core.executor.a(1), new androidx.core.os.c(c5028l));
        Object objQ = c5028l.q();
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        if (objQ == aVar) {
            Intrinsics.checkNotNullParameter(frame, "frame");
        }
        return objQ == aVar ? objQ : Unit.a;
    }

    public static Object l(e eVar, g gVar, kotlin.coroutines.h<? super Unit> hVar) {
        new C5028l(1, kotlin.coroutines.intrinsics.h.b(hVar)).r();
        MeasurementManager measurementManager = eVar.a;
        throw null;
    }

    public static Object n(e eVar, h hVar, kotlin.coroutines.h<? super Unit> hVar2) {
        new C5028l(1, kotlin.coroutines.intrinsics.h.b(hVar2)).r();
        MeasurementManager measurementManager = eVar.a;
        throw null;
    }

    public Object a(@NotNull a aVar, @NotNull kotlin.coroutines.h<? super Unit> hVar) {
        return b(this, aVar, hVar);
    }

    public Object c(@NotNull kotlin.coroutines.h<? super Integer> hVar) {
        return d(this, hVar);
    }

    public Object e(@NotNull Uri uri, InputEvent inputEvent, @NotNull kotlin.coroutines.h<? super Unit> hVar) {
        return g(this, uri, inputEvent, hVar);
    }

    public Object f(@NotNull f fVar, @NotNull kotlin.coroutines.h<? super Unit> hVar) {
        return h(this, fVar, hVar);
    }

    public Object i(@NotNull Uri uri, @NotNull kotlin.coroutines.h<? super Unit> hVar) {
        return j(this, uri, hVar);
    }

    public Object k(@NotNull g gVar, @NotNull kotlin.coroutines.h<? super Unit> hVar) {
        return l(this, gVar, hVar);
    }

    public Object m(@NotNull h hVar, @NotNull kotlin.coroutines.h<? super Unit> hVar2) {
        return n(this, hVar, hVar2);
    }
}
