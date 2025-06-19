package androidx.compose.ui.input.nestedscroll;

import android.content.Context;
import android.view.View;
import android.view.inputmethod.BaseInputConnection;
import android.view.inputmethod.InputMethodManager;
import androidx.appcompat.widget.C0122z;
import androidx.compose.runtime.AbstractC0772a;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.L0;
import androidx.compose.ui.layout.C0903y;
import androidx.compose.ui.layout.G;
import androidx.compose.ui.layout.e0;
import androidx.compose.ui.node.C0907c;
import androidx.compose.ui.node.E;
import androidx.compose.ui.node.F;
import androidx.compose.ui.node.J;
import androidx.compose.ui.node.K;
import androidx.compose.ui.node.L;
import androidx.compose.ui.node.a0;
import androidx.compose.ui.p;
import androidx.compose.ui.platform.V;
import androidx.compose.ui.platform.W;
import androidx.compose.ui.text.input.C;
import androidx.compose.ui.window.u;
import androidx.credentials.exceptions.ClearCredentialUnsupportedException;
import androidx.credentials.exceptions.GetCredentialUnsupportedException;
import androidx.credentials.playservices.controllers.BeginSignIn.CredentialProviderBeginSignInController;
import androidx.credentials.playservices.controllers.GetSignInIntent.CredentialProviderGetSignInIntentController;
import androidx.datastore.core.InterfaceC1076h;
import androidx.datastore.core.U;
import androidx.glance.appwidget.C1182m;
import androidx.glance.appwidget.P;
import androidx.glance.appwidget.X;
import androidx.glance.session.C1229g;
import androidx.glance.session.C1231i;
import androidx.glance.session.SessionWorker;
import androidx.paging.C1335q;
import androidx.paging.N;
import com.comscore.streaming.EventType;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import java.io.File;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import kotlin.Unit;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.C4956o;
import kotlin.jvm.internal.I;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.r;
import kotlinx.coroutines.C5027k0;
import kotlinx.coroutines.flow.InterfaceC4992i;
import kotlinx.coroutines.flow.d0;

/* loaded from: classes.dex */
public final class b extends r implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ b(Object obj, int i) {
        super(0);
        this.a = i;
        this.b = obj;
    }

    /* JADX WARN: Type inference failed for: r0v82, types: [kotlin.jvm.functions.Function0, kotlin.jvm.internal.o] */
    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        InterfaceC1076h interfaceC1076h;
        androidx.sqlite.db.framework.f sQLiteOpenHelper;
        int i = 0;
        z = false;
        boolean z = false;
        int i2 = 0;
        androidx.compose.ui.layout.r rVar = null;
        switch (this.a) {
            case 0:
                return ((e) this.b).c;
            case 1:
                return ((i) this.b).M0();
            case 2:
                G gA = ((e0) this.b).a();
                E e = gA.a;
                if (gA.n != ((androidx.compose.runtime.collection.b) ((androidx.collection.E) e.p()).b).c) {
                    Iterator it2 = gA.f.entrySet().iterator();
                    while (it2.hasNext()) {
                        ((C0903y) ((Map.Entry) it2.next()).getValue()).d = true;
                    }
                    if (!e.x.d) {
                        E.T(e, false, 7);
                    }
                }
                return Unit.a;
            case 3:
                androidx.compose.ui.modifier.d dVar = (androidx.compose.ui.modifier.d) this.b;
                dVar.f = false;
                HashSet hashSet = new HashSet();
                androidx.compose.runtime.collection.b bVar = dVar.d;
                int i3 = bVar.c;
                androidx.compose.runtime.collection.b bVar2 = dVar.e;
                if (i3 > 0) {
                    Object[] objArr = bVar.a;
                    int i4 = 0;
                    do {
                        E e2 = (E) objArr[i4];
                        androidx.compose.ui.modifier.h hVar = (androidx.compose.ui.modifier.h) bVar2.a[i4];
                        p pVar = (p) e2.w.f;
                        if (pVar.m) {
                            androidx.compose.ui.modifier.d.b(pVar, hVar, hashSet);
                        }
                        i4++;
                    } while (i4 < i3);
                }
                bVar.i();
                bVar2.i();
                androidx.compose.runtime.collection.b bVar3 = dVar.b;
                int i5 = bVar3.c;
                androidx.compose.runtime.collection.b bVar4 = dVar.c;
                if (i5 > 0) {
                    Object[] objArr2 = bVar3.a;
                    do {
                        C0907c c0907c = (C0907c) objArr2[i];
                        androidx.compose.ui.modifier.h hVar2 = (androidx.compose.ui.modifier.h) bVar4.a[i];
                        if (c0907c.m) {
                            androidx.compose.ui.modifier.d.b(c0907c, hVar2, hashSet);
                        }
                        i++;
                    } while (i < i5);
                }
                bVar3.i();
                bVar4.i();
                Iterator it3 = hashSet.iterator();
                while (it3.hasNext()) {
                    ((C0907c) it3.next()).O0();
                }
                return Unit.a;
            case 4:
                L l = ((E) this.b).x;
                l.r.w = true;
                J j = l.s;
                if (j != null) {
                    j.t = true;
                }
                return Unit.a;
            case 5:
                K k = (K) this.b;
                L l2 = k.H;
                l2.k = 0;
                androidx.compose.runtime.collection.b bVarW = l2.a.w();
                int i6 = bVarW.c;
                if (i6 > 0) {
                    Object[] objArr3 = bVarW.a;
                    int i7 = 0;
                    do {
                        K k2 = ((E) objArr3[i7]).x.r;
                        k2.g = k2.h;
                        k2.h = SubsamplingScaleImageView.TILE_SIZE_AUTO;
                        k2.t = false;
                        if (k2.k == 2) {
                            k2.k = 3;
                        }
                        i7++;
                    } while (i7 < i6);
                }
                L l3 = k.H;
                androidx.compose.runtime.collection.b bVarW2 = l3.a.w();
                int i8 = bVarW2.c;
                if (i8 > 0) {
                    Object[] objArr4 = bVarW2.a;
                    int i9 = 0;
                    do {
                        ((E) objArr4[i9]).x.r.u.d = false;
                        Unit unit = Unit.a;
                        i9++;
                    } while (i9 < i8);
                }
                k.e().F0().d();
                E e3 = l3.a;
                androidx.compose.runtime.collection.b bVarW3 = e3.w();
                int i10 = bVarW3.c;
                if (i10 > 0) {
                    Object[] objArr5 = bVarW3.a;
                    int i11 = 0;
                    do {
                        E e4 = (E) objArr5[i11];
                        if (e4.x.r.g != e4.t()) {
                            e3.K();
                            e3.z();
                            if (e4.t() == Integer.MAX_VALUE) {
                                e4.x.r.B0();
                            }
                        }
                        i11++;
                    } while (i11 < i10);
                }
                androidx.compose.runtime.collection.b bVarW4 = e3.w();
                int i12 = bVarW4.c;
                if (i12 > 0) {
                    Object[] objArr6 = bVarW4.a;
                    do {
                        F f = ((E) objArr6[i2]).x.r.u;
                        f.e = f.d;
                        Unit unit2 = Unit.a;
                        i2++;
                    } while (i2 < i12);
                }
                return Unit.a;
            case 6:
                L l4 = (L) this.b;
                l4.a().B(l4.t);
                return Unit.a;
            case 7:
                a0 a0Var = ((a0) this.b).n;
                if (a0Var != null) {
                    a0Var.c1();
                }
                return Unit.a;
            case 8:
                kotlinx.coroutines.E.i(((V) this.b).c, null);
                return Unit.a;
            case 9:
                ((W) this.b).b = null;
                return Unit.a;
            case 10:
                ((Function0) ((kotlin.jvm.internal.J) this.b).a).invoke();
                return Unit.a;
            case 11:
                Object systemService = ((View) ((com.quizlet.data.repository.set.f) this.b).b).getContext().getSystemService("input_method");
                Intrinsics.e(systemService, "null cannot be cast to non-null type android.view.inputmethod.InputMethodManager");
                return (InputMethodManager) systemService;
            case 12:
                return new BaseInputConnection(((androidx.compose.ui.text.input.E) this.b).a, false);
            case 13:
                androidx.compose.ui.text.platform.style.b bVar5 = (androidx.compose.ui.text.platform.style.b) this.b;
                if (((androidx.compose.ui.geometry.e) ((L0) bVar5.c).getValue()).a == 9205357640488583168L) {
                    return null;
                }
                InterfaceC0773a0 interfaceC0773a0 = bVar5.c;
                if (androidx.compose.ui.geometry.e.e(((androidx.compose.ui.geometry.e) ((L0) interfaceC0773a0).getValue()).a)) {
                    return null;
                }
                return bVar5.a.b(((androidx.compose.ui.geometry.e) ((L0) interfaceC0773a0).getValue()).a);
            case 14:
                u uVar = (u) this.b;
                androidx.compose.ui.layout.r parentLayoutCoordinates = uVar.getParentLayoutCoordinates();
                if (parentLayoutCoordinates != null && parentLayoutCoordinates.k()) {
                    rVar = parentLayoutCoordinates;
                }
                if (rVar != null && uVar.m5getPopupContentSizebOM6tXw() != null) {
                    z = true;
                }
                return Boolean.valueOf(z);
            case 15:
                ((androidx.credentials.c) this.b).b(new ClearCredentialUnsupportedException("Your device doesn't support credential manager"));
                return Unit.a;
            case 16:
                ((androidx.credentials.d) this.b).b(new GetCredentialUnsupportedException("Your device doesn't support credential manager"));
                return Unit.a;
            case 17:
                CredentialProviderBeginSignInController credentialProviderBeginSignInController = (CredentialProviderBeginSignInController) this.b;
                credentialProviderBeginSignInController.g().execute(new C(credentialProviderBeginSignInController, 4));
                return Unit.a;
            case 18:
                CredentialProviderGetSignInIntentController credentialProviderGetSignInIntentController = (CredentialProviderGetSignInIntentController) this.b;
                credentialProviderGetSignInIntentController.h().execute(new C(credentialProviderGetSignInIntentController, 5));
                return Unit.a;
            case 19:
                Object obj = U.d;
                File file = (File) this.b;
                synchronized (obj) {
                    U.c.remove(file.getAbsolutePath());
                }
                return Unit.a;
            case 20:
                return ((C4956o) this.b).invoke();
            case 21:
                ((L0) ((C1182m) this.b).i).getValue();
                return Unit.a;
            case EventType.WINDOW_STATE /* 22 */:
                X x = (X) this.b;
                synchronized (X.d) {
                    interfaceC1076h = X.f;
                    if (interfaceC1076h == null) {
                        interfaceC1076h = (InterfaceC1076h) X.e.a(x.a, P.a[0]);
                        X.f = interfaceC1076h;
                    }
                }
                return interfaceC1076h;
            case EventType.AUDIO /* 23 */:
                C1231i c1231i = (C1231i) this.b;
                c1231i.getClass();
                long jNanoTime = System.nanoTime();
                I i13 = new I();
                I i14 = new I();
                synchronized (c1231i.c) {
                    i13.a = jNanoTime - c1231i.e;
                    i14.a = 1000000000 / c1231i.d;
                    Unit unit3 = Unit.a;
                }
                kotlinx.coroutines.E.A(c1231i.a, null, null, new C1229g(i13, i14, c1231i, jNanoTime, null), 3);
                return Unit.a;
            case EventType.VIDEO /* 24 */:
                C5027k0 c5027k0D = kotlinx.coroutines.E.d();
                ((SessionWorker) this.b).getClass();
                return c5027k0D;
            case EventType.SUBS /* 25 */:
                N n = (N) CollectionsKt.firstOrNull(((C1335q) ((C0122z) ((androidx.paging.I) this.b).b.b).c).b());
                if (n == null || !(n instanceof androidx.paging.L)) {
                    return null;
                }
                androidx.paging.L l5 = (androidx.paging.L) n;
                if (l5.a == androidx.paging.G.a) {
                    return l5;
                }
                return null;
            case EventType.CDN /* 26 */:
                d0 d0Var = ((androidx.paging.compose.c) this.b).l;
                Unit unit4 = Unit.a;
                d0Var.h(unit4);
                return unit4;
            case 27:
                return ((AbstractC0772a) this.b).g();
            case 28:
                androidx.sqlite.db.framework.g gVar = (androidx.sqlite.db.framework.g) this.b;
                if (gVar.b == null || !gVar.d) {
                    sQLiteOpenHelper = new androidx.sqlite.db.framework.f(gVar.a, gVar.b, new com.airbnb.lottie.network.c(13), gVar.c, gVar.e);
                } else {
                    Context context = gVar.a;
                    Intrinsics.checkNotNullParameter(context, "context");
                    File noBackupFilesDir = context.getNoBackupFilesDir();
                    Intrinsics.checkNotNullExpressionValue(noBackupFilesDir, "context.noBackupFilesDir");
                    sQLiteOpenHelper = new androidx.sqlite.db.framework.f(gVar.a, new File(noBackupFilesDir, gVar.b).getAbsolutePath(), new com.airbnb.lottie.network.c(13), gVar.c, gVar.e);
                }
                boolean z2 = gVar.g;
                Intrinsics.checkNotNullParameter(sQLiteOpenHelper, "sQLiteOpenHelper");
                sQLiteOpenHelper.setWriteAheadLoggingEnabled(z2);
                return sQLiteOpenHelper;
            default:
                return new androidx.work.impl.constraints.c[((InterfaceC4992i[]) this.b).length];
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    /* JADX WARN: Multi-variable type inference failed */
    public b(Function0 function0) {
        super(0);
        this.a = 20;
        this.b = (C4956o) function0;
    }
}
