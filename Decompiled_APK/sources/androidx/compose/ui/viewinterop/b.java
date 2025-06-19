package androidx.compose.ui.viewinterop;

import android.animation.Animator;
import android.app.Activity;
import android.content.Context;
import android.content.SharedPreferences;
import android.view.View;
import android.view.ViewGroup;
import androidx.activity.result.ActivityResult;
import androidx.compose.runtime.C0775b0;
import androidx.compose.ui.node.E;
import androidx.compose.ui.q;
import androidx.compose.ui.text.C0981a;
import androidx.compose.ui.window.u;
import androidx.compose.ui.window.x;
import androidx.datastore.core.b0;
import androidx.fragment.app.AbstractC1136h0;
import androidx.fragment.app.Fragment;
import androidx.fragment.app.I;
import androidx.paging.C1325l;
import androidx.paging.D;
import androidx.paging.F;
import androidx.paging.G;
import androidx.work.impl.WorkerStoppedException;
import androidx.work.y;
import assistantMode.types.A;
import assistantMode.types.C1454a;
import com.comscore.streaming.EventType;
import com.mayakapps.kache.C4040i;
import com.mayakapps.kache.H;
import com.quizlet.features.flashcards.C4237k;
import com.quizlet.quizletandroid.R;
import java.io.UnsupportedEncodingException;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.concurrent.CancellationException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.r;
import kotlinx.coroutines.C;
import kotlinx.coroutines.channels.t;
import kotlinx.coroutines.y0;

/* loaded from: classes.dex */
public final class b extends r implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;
    public final /* synthetic */ Object c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ b(int i, Object obj, Object obj2) {
        super(1);
        this.a = i;
        this.b = obj;
        this.c = obj2;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) throws IllegalAccessException, IllegalArgumentException, UnsupportedEncodingException {
        AbstractC1136h0 childFragmentManager;
        Unit unit;
        F f;
        F fA;
        int i = 5;
        int i2 = 2;
        int i3 = 4;
        AbstractC1136h0 supportFragmentManager = null;
        int i4 = 0;
        int i5 = 1;
        switch (this.a) {
            case 0:
                View view = (View) obj;
                Object tag = view.getTag(R.id.binding_reference);
                Intrinsics.e(tag, "null cannot be cast to non-null type T of androidx.compose.ui.viewinterop.AndroidViewBindingKt.getBinding");
                Unit unit2 = Unit.a;
                ViewGroup viewGroup = view instanceof ViewGroup ? (ViewGroup) view : null;
                if (viewGroup != null) {
                    Fragment fragment = (Fragment) this.b;
                    if (fragment == null || (childFragmentManager = fragment.getChildFragmentManager()) == null) {
                        Context context = (Context) this.c;
                        I i6 = context instanceof I ? (I) context : null;
                        if (i6 != null) {
                            supportFragmentManager = i6.getSupportFragmentManager();
                        }
                    } else {
                        supportFragmentManager = childFragmentManager;
                    }
                    k.k(viewGroup, new C0775b0(supportFragmentManager, 26));
                }
                return Unit.a;
            case 1:
                ((E) this.b).Z(((q) obj).g((q) this.c));
                return Unit.a;
            case 2:
                u uVar = (u) this.b;
                uVar.setPositionProvider((x) this.c);
                uVar.i();
                return new androidx.compose.ui.window.h();
            case 3:
                Throwable th = (Throwable) obj;
                ((androidx.credentials.playservices.controllers.BeginSignIn.c) this.b).invoke(th);
                com.quizlet.data.repository.explanations.question.a aVar = (com.quizlet.data.repository.explanations.question.a) this.c;
                ((kotlinx.coroutines.channels.h) aVar.c).k(th, false);
                do {
                    Object objB = kotlinx.coroutines.channels.o.b(((kotlinx.coroutines.channels.h) aVar.c).h());
                    if (objB != null) {
                        b0 msg = (b0) objB;
                        Intrinsics.checkNotNullParameter(msg, "msg");
                        msg.b.k0(th == null ? new CancellationException("DataStore scope was cancelled before updateData could complete") : th);
                        Unit unit3 = Unit.a;
                        unit = Unit.a;
                    } else {
                        unit = null;
                    }
                } while (unit != null);
                return Unit.a;
            case 4:
                if (((AtomicBoolean) this.b).compareAndSet(false, true)) {
                    ((kotlinx.coroutines.channels.h) this.c).o(Unit.a);
                }
                return Unit.a;
            case 5:
                C1325l c1325l = (C1325l) obj;
                if (c1325l == null || (f = c1325l.d) == null) {
                    f = F.f;
                }
                F f2 = c1325l != null ? c1325l.e : null;
                G loadType = (G) this.b;
                f.getClass();
                D newState = D.c;
                Intrinsics.checkNotNullParameter(loadType, "loadType");
                Intrinsics.checkNotNullParameter(newState, "newState");
                int iOrdinal = loadType.ordinal();
                if (iOrdinal == 0) {
                    fA = F.a(f, 6);
                } else if (iOrdinal == 1) {
                    fA = F.a(f, 5);
                } else {
                    if (iOrdinal != 2) {
                        throw new NoWhenBranchMatchedException();
                    }
                    fA = F.a(f, 3);
                }
                return com.quizlet.data.repository.user.a.b((com.quizlet.data.repository.user.a) this.c, c1325l, fA, f2);
            case 6:
                Throwable th2 = (Throwable) obj;
                androidx.concurrent.futures.i iVar = (androidx.concurrent.futures.i) this.b;
                if (th2 == null) {
                    iVar.b(((kotlinx.coroutines.I) this.c).I());
                } else if (th2 instanceof CancellationException) {
                    iVar.c();
                } else {
                    iVar.d(th2);
                }
                return Unit.a;
            case 7:
                Throwable th3 = (Throwable) obj;
                if (th3 instanceof WorkerStoppedException) {
                    ((y) this.b).stop(((WorkerStoppedException) th3).a);
                }
                ((com.google.common.util.concurrent.e) this.c).cancel(false);
                return Unit.a;
            case 8:
                androidx.work.impl.constraints.c it2 = (androidx.work.impl.constraints.c) obj;
                Intrinsics.checkNotNullParameter(it2, "it");
                ((y0) this.b).j(null);
                ((t) ((kotlinx.coroutines.channels.u) this.c)).o(it2);
                return Unit.a;
            case 9:
                ActivityResult result = (ActivityResult) obj;
                Intrinsics.checkNotNullParameter(result, "result");
                if (result.a == -1) {
                    ((com.facebook.login.u) this.b).G().j(assistantMode.refactored.a.a(1), result.a, result.b);
                } else {
                    ((I) this.c).finish();
                }
                return Unit.a;
            case 10:
                C4040i InMemoryKache = (C4040i) obj;
                Intrinsics.checkNotNullParameter(InMemoryKache, "$this$InMemoryKache");
                InMemoryKache.getClass();
                com.mayakapps.kache.x xVar = (com.mayakapps.kache.x) this.b;
                Intrinsics.checkNotNullParameter(xVar, "<set-?>");
                InMemoryKache.a = xVar;
                H h = (H) this.c;
                C0981a c0981a = new C0981a(h, 7);
                Intrinsics.checkNotNullParameter(c0981a, "<set-?>");
                InMemoryKache.c = c0981a;
                androidx.compose.foundation.lazy.f fVar = new androidx.compose.foundation.lazy.f(h, i3);
                Intrinsics.checkNotNullParameter(fVar, "<set-?>");
                InMemoryKache.d = fVar;
                C c = h.c;
                Intrinsics.checkNotNullParameter(c, "<set-?>");
                InMemoryKache.b = c;
                return Unit.a;
            case 11:
                int iIntValue = ((Number) obj).intValue();
                return ((androidx.navigation.compose.x) this.b).invoke(Integer.valueOf(iIntValue), ((kotlinx.collections.immutable.b) this.c).get(iIntValue));
            case 12:
                int iIntValue2 = ((Number) obj).intValue();
                return ((androidx.navigation.compose.x) this.b).invoke(Integer.valueOf(iIntValue2), ((kotlinx.collections.immutable.b) this.c).get(iIntValue2));
            case 13:
                int iIntValue3 = ((Number) obj).intValue();
                return ((androidx.navigation.compose.x) this.b).invoke(Integer.valueOf(iIntValue3), ((kotlinx.collections.immutable.b) this.c).get(iIntValue3));
            case 14:
                int iIntValue4 = ((Number) obj).intValue();
                return ((androidx.navigation.compose.x) this.b).invoke(Integer.valueOf(iIntValue4), ((List) this.c).get(iIntValue4));
            case 15:
                return ((C4237k) this.b).invoke(((List) this.c).get(((Number) obj).intValue()));
            case 16:
                return ((C4237k) this.b).invoke(((List) this.c).get(((Number) obj).intValue()));
            case 17:
                return ((C4237k) this.b).invoke(((kotlinx.collections.immutable.e) this.c).get(((Number) obj).intValue()));
            case 18:
                return ((com.quizlet.features.practicetest.navigation.a) this.b).invoke(((List) this.c).get(((Number) obj).intValue()));
            case 19:
                int iIntValue5 = ((Number) obj).intValue();
                return ((androidx.navigation.compose.x) this.b).invoke(Integer.valueOf(iIntValue5), ((kotlinx.collections.immutable.e) this.c).get(iIntValue5));
            case 20:
                int iIntValue6 = ((Number) obj).intValue();
                return ((androidx.navigation.compose.x) this.b).invoke(Integer.valueOf(iIntValue6), ((kotlinx.collections.immutable.e) this.c).get(iIntValue6));
            case 21:
                int iIntValue7 = ((Number) obj).intValue();
                return ((androidx.navigation.compose.x) this.b).invoke(Integer.valueOf(iIntValue7), ((List) this.c).get(iIntValue7));
            case EventType.WINDOW_STATE /* 22 */:
                int iIntValue8 = ((Number) obj).intValue();
                return ((androidx.navigation.compose.x) this.b).invoke(Integer.valueOf(iIntValue8), ((List) this.c).get(iIntValue8));
            case EventType.AUDIO /* 23 */:
                int iIntValue9 = ((Number) obj).intValue();
                return ((androidx.navigation.compose.x) this.b).invoke(Integer.valueOf(iIntValue9), ((List) this.c).get(iIntValue9));
            case EventType.VIDEO /* 24 */:
                int iIntValue10 = ((Number) obj).intValue();
                return ((androidx.navigation.compose.x) this.b).invoke(Integer.valueOf(iIntValue10), ((List) this.c).get(iIntValue10));
            case EventType.SUBS /* 25 */:
                app.cash.sqldelight.driver.android.j executeQuery = (app.cash.sqldelight.driver.android.j) obj;
                Intrinsics.checkNotNullParameter(executeQuery, "$this$executeQuery");
                com.quizlet.shared.persistence.db.c cVar = (com.quizlet.shared.persistence.db.c) this.b;
                executeQuery.b(0, Long.valueOf(cVar.c));
                com.quizlet.data.repository.login.a aVar2 = ((com.quizlet.shared.persistence.db.g) this.c).c;
                executeQuery.b(1, (Long) ((com.quizlet.quizletandroid.ui.joincontenttofolder.i) aVar2.b).b(cVar.d));
                executeQuery.b(2, (Long) ((com.quizlet.quizletandroid.ui.joincontenttofolder.i) aVar2.a).b(cVar.e));
                return Unit.a;
            case EventType.CDN /* 26 */:
                com.snowplowanalytics.core.tracker.d dVar = (com.snowplowanalytics.core.tracker.d) obj;
                com.snowplowanalytics.core.tracker.b bVar = (com.snowplowanalytics.core.tracker.b) this.b;
                if (dVar != null) {
                    bVar.a.add(dVar);
                }
                HashMap map = new HashMap();
                map.put("event", bVar);
                com.snowplowanalytics.core.utils.c.b(map, "SnowplowInstallTracking");
                StringBuilder sb = new StringBuilder();
                Activity activity = (Activity) this.c;
                sb.append(activity.getPackageName());
                sb.append("_preferences");
                SharedPreferences.Editor editorEdit = activity.getSharedPreferences(sb.toString(), 0).edit();
                if (editorEdit != null) {
                    editorEdit.putString("installed_before", "YES");
                }
                if (editorEdit != null) {
                    editorEdit.apply();
                }
                return Unit.a;
            case 27:
                com.snowplowanalytics.core.tracker.n tracker = (com.snowplowanalytics.core.tracker.n) obj;
                Intrinsics.checkNotNullParameter(tracker, "tracker");
                tracker.i = (com.snowplowanalytics.core.tracker.l) this.b;
                String strV = ((com.snowplowanalytics.core.tracker.k) this.c).f().v();
                if (!tracker.b) {
                    tracker.x = strV;
                }
                boolean zC = ((com.snowplowanalytics.core.tracker.k) this.c).f().c();
                if (!tracker.b) {
                    tracker.k = zC;
                }
                com.snowplowanalytics.snowplow.tracker.a aVarE = ((com.snowplowanalytics.core.tracker.k) this.c).f().e();
                Intrinsics.checkNotNullParameter(aVarE, "<set-?>");
                tracker.l = aVarE;
                com.snowplowanalytics.snowplow.tracker.b level = ((com.snowplowanalytics.core.tracker.k) this.c).f().l();
                Intrinsics.checkNotNullParameter(level, "level");
                if (!tracker.b) {
                    tracker.m = level;
                }
                com.snowplowanalytics.snowplow.tracker.c cVarM = ((com.snowplowanalytics.core.tracker.k) this.c).f().m();
                if (!tracker.b) {
                    if (cVarM == null) {
                        cVarM = new com.quizlet.quizletandroid.ui.folder.logging.a(i);
                    }
                    com.snowplowanalytics.core.tracker.e.b = cVarM;
                }
                boolean zU = ((com.snowplowanalytics.core.tracker.k) this.c).f().u();
                synchronized (tracker) {
                    try {
                        tracker.z = zU;
                        com.snowplowanalytics.core.session.c cVar2 = tracker.j;
                        if (cVar2 != null && !zU) {
                            tracker.b();
                            tracker.j = null;
                        } else if (cVar2 == null && zU) {
                            Runnable[] runnableArr = {null, null, null, null};
                            Runnable[] runnableArr2 = tracker.y;
                            tracker.j = com.snowplowanalytics.core.session.c.q.a(tracker.c, tracker.n, tracker.o, tracker.q, runnableArr2.length == 4 ? runnableArr2 : runnableArr, tracker.p);
                        }
                    } catch (Throwable th4) {
                        throw th4;
                    }
                }
                boolean zB = ((com.snowplowanalytics.core.tracker.k) this.c).f().b();
                if (!tracker.b) {
                    tracker.C = zB;
                }
                boolean zN = ((com.snowplowanalytics.core.tracker.k) this.c).f().n();
                if (!tracker.b) {
                    tracker.B = zN;
                }
                boolean zH = ((com.snowplowanalytics.core.tracker.k) this.c).f().h();
                if (!tracker.b) {
                    tracker.A = zH;
                }
                if (((com.snowplowanalytics.core.tracker.k) this.c).f().d()) {
                    tracker.a(new com.snowplowanalytics.core.screenviews.b(i2));
                } else {
                    Intrinsics.checkNotNullParameter("DeepLinkContext", "identifier");
                    tracker.d.q("DeepLinkContext");
                }
                if (((com.snowplowanalytics.core.tracker.k) this.c).f().q()) {
                    tracker.a(new com.snowplowanalytics.core.screenviews.b(i4));
                } else {
                    Intrinsics.checkNotNullParameter("ScreenContext", "identifier");
                    tracker.d.q("ScreenContext");
                }
                boolean zT = ((com.snowplowanalytics.core.tracker.k) this.c).f().t();
                if (!tracker.b) {
                    tracker.v = zT;
                }
                if (((com.snowplowanalytics.core.tracker.k) this.c).f().s()) {
                    tracker.a(new com.snowplowanalytics.core.screenviews.b(i5));
                } else {
                    Intrinsics.checkNotNullParameter("ScreenSummaryContext", "identifier");
                    tracker.d.q("ScreenSummaryContext");
                }
                boolean zK = ((com.snowplowanalytics.core.tracker.k) this.c).f().k();
                if (!tracker.b) {
                    tracker.t = zK;
                }
                boolean zJ = ((com.snowplowanalytics.core.tracker.k) this.c).f().j();
                if (!tracker.b) {
                    tracker.u = zJ;
                }
                boolean zG = ((com.snowplowanalytics.core.tracker.k) this.c).f().g();
                if (!tracker.b) {
                    tracker.r = zG;
                }
                boolean zF = ((com.snowplowanalytics.core.tracker.k) this.c).f().f();
                if (!tracker.b) {
                    tracker.s = zF;
                }
                boolean zW = ((com.snowplowanalytics.core.tracker.k) this.c).f().w();
                boolean z = tracker.b;
                if (!z) {
                    tracker.w = zW;
                } else if (tracker.w != zW && z) {
                    tracker.w = zW;
                    com.snowplowanalytics.core.session.c cVar3 = tracker.j;
                    if (cVar3 != null) {
                        cVar3.g.set(true);
                    }
                }
                String strV2 = ((com.snowplowanalytics.core.tracker.k) this.c).f().v();
                if (!tracker.b) {
                    tracker.x = strV2;
                }
                com.snowplowanalytics.snowplow.configuration.c cVar4 = ((com.snowplowanalytics.core.tracker.k) this.c).l;
                if (cVar4 == null) {
                    Intrinsics.m("gdprConfiguration");
                    throw null;
                }
                com.snowplowanalytics.snowplow.configuration.c cVar5 = cVar4.a;
                if (cVar5 != null) {
                    tracker.D = new com.quizlet.data.repository.classmembership.c(cVar5.a(), cVar5.c(), cVar5.d(), cVar5.b());
                }
                com.snowplowanalytics.snowplow.util.c cVarA = ((com.snowplowanalytics.core.tracker.k) this.c).e().a();
                TimeUnit timeUnit = TimeUnit.SECONDS;
                long jA = cVarA.a(timeUnit);
                if (!tracker.b) {
                    tracker.o = jA;
                }
                long jA2 = ((com.snowplowanalytics.core.tracker.k) this.c).e().c().a(timeUnit);
                if (!tracker.b) {
                    tracker.n = jA2;
                }
                boolean zB2 = ((com.snowplowanalytics.core.tracker.k) this.c).e().b();
                if (!tracker.b) {
                    tracker.p = zB2;
                    com.snowplowanalytics.core.session.c cVar6 = tracker.j;
                    if (cVar6 != null) {
                        cVar6.a = zB2;
                    }
                }
                Iterator it3 = ((com.snowplowanalytics.core.tracker.k) this.c).m.iterator();
                while (it3.hasNext()) {
                    com.snowplowanalytics.core.globalcontexts.a aVar3 = (com.snowplowanalytics.core.globalcontexts.a) it3.next();
                    Intrinsics.checkNotNullParameter(aVar3, "<this>");
                    com.snowplowanalytics.core.globalcontexts.a aVar4 = aVar3 != null ? aVar3 : null;
                    tracker.a(new com.snowplowanalytics.core.statemachine.c(aVar3.a, aVar4 != null ? new com.quizlet.quizletandroid.ui.activitycenter.views.i(new com.iabtcf.decoder.d(aVar4.b, i5)) : null));
                }
                return Unit.a;
            case 28:
                Intrinsics.f((Animator) obj, "it");
                ((it.sephiroth.android.library.xtooltip.g) this.b).setVisibility(4);
                ((it.sephiroth.android.library.xtooltip.i) this.c).a();
                return Unit.a;
            default:
                Intrinsics.checkNotNullParameter((A) obj, "<name for destructuring parameter 0>");
                return Boolean.valueOf(!((LinkedHashSet) this.b).contains(((C1454a) this.c).d(r0.a)));
        }
    }
}
