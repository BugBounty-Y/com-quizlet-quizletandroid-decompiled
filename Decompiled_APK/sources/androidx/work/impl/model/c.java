package androidx.work.impl.model;

import android.content.Context;
import android.content.Intent;
import android.content.pm.ShortcutInfo;
import android.content.pm.ShortcutManager;
import android.content.res.Resources;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.text.TextUtils;
import android.util.SparseArray;
import android.util.SparseIntArray;
import androidx.appcompat.app.K;
import androidx.appcompat.app.Q;
import androidx.camera.camera2.internal.compat.quirk.ExtraSupportedOutputSizeQuirk;
import androidx.compose.foundation.lazy.A;
import androidx.lifecycle.u0;
import androidx.work.impl.C1433e;
import androidx.work.impl.WorkDatabase_Impl;
import com.android.billingclient.api.z;
import com.facebook.FacebookException;
import com.facebook.login.C;
import com.google.android.gms.common.GoogleApiAvailability;
import com.google.android.gms.internal.measurement.C3008j0;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3215n6;
import com.google.android.gms.internal.mlkit_vision_camera.W1;
import com.google.android.gms.internal.play_billing.AbstractC3819n0;
import com.google.android.gms.internal.play_billing.K1;
import com.google.android.gms.internal.play_billing.M1;
import com.google.android.gms.internal.play_billing.Q1;
import com.google.android.gms.internal.play_billing.U1;
import com.google.android.gms.internal.play_billing.b2;
import com.google.android.gms.internal.play_billing.c2;
import com.google.android.gms.internal.play_billing.f2;
import com.google.android.gms.internal.play_billing.g2;
import com.google.android.gms.measurement.internal.AbstractC3893t;
import com.google.android.gms.measurement.internal.C3902x0;
import com.google.android.gms.measurement.internal.D0;
import com.google.android.gms.measurement.internal.O;
import com.google.android.gms.measurement.internal.Y;
import com.google.android.gms.measurement.internal.zzov;
import com.onetrust.otpublishers.headless.Public.OTCallback;
import com.onetrust.otpublishers.headless.Public.Response.OTResponse;
import com.quizlet.db.data.caches.UserInfoCache;
import com.quizlet.db.data.models.persisted.DBImage;
import com.quizlet.db.data.models.persisted.DBTerm;
import com.quizlet.generated.enums.G;
import com.quizlet.generated.enums.H;
import com.quizlet.generated.enums.I;
import com.quizlet.generated.enums.J;
import com.quizlet.local.datastore.preferences.C4566c0;
import com.skydoves.balloon.internals.DefinitionKt;
import io.reactivex.rxjava3.internal.operators.maybe.w;
import io.reactivex.rxjava3.internal.operators.observable.C4887f;
import io.reactivex.rxjava3.internal.operators.observable.o0;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.AbstractC5040y;
import org.json.JSONException;

/* loaded from: classes.dex */
public final class c implements androidx.compose.foundation.gestures.snapping.m, z, com.google.common.util.concurrent.c, OTCallback, com.facebook.l, io.reactivex.rxjava3.functions.h {
    public final /* synthetic */ int a;
    public Object b;
    public final Object c;

    public /* synthetic */ c(int i, Object obj, Object obj2) {
        this.a = i;
        this.b = obj;
        this.c = obj2;
    }

    public int A(Context context, com.google.android.gms.common.api.c cVar) {
        int i;
        int iC;
        com.google.android.gms.common.internal.u.h(context);
        com.google.android.gms.common.internal.u.h(cVar);
        int iA = cVar.a();
        SparseIntArray sparseIntArray = (SparseIntArray) this.b;
        synchronized (sparseIntArray) {
            i = sparseIntArray.get(iA, -1);
        }
        if (i != -1) {
            return i;
        }
        SparseIntArray sparseIntArray2 = (SparseIntArray) this.b;
        synchronized (sparseIntArray2) {
            iC = 0;
            int i2 = 0;
            while (true) {
                try {
                    if (i2 >= sparseIntArray2.size()) {
                        iC = -1;
                        break;
                    }
                    int iKeyAt = sparseIntArray2.keyAt(i2);
                    if (iKeyAt > iA && sparseIntArray2.get(iKeyAt) == 0) {
                        break;
                    }
                    i2++;
                } catch (Throwable th) {
                    throw th;
                }
            }
            if (iC == -1) {
                iC = ((GoogleApiAvailability) this.c).c(context, iA);
            }
            sparseIntArray2.put(iA, iC);
        }
        return iC;
    }

    public void B() throws JSONException {
        Y y = (Y) ((D0) this.c).b;
        O o = y.h;
        Y.h(o);
        SparseArray sparseArrayY = o.Y();
        zzov zzovVar = (zzov) this.b;
        sparseArrayY.put(zzovVar.c, Long.valueOf(zzovVar.b));
        O o2 = y.h;
        Y.h(o2);
        int[] iArr = new int[sparseArrayY.size()];
        long[] jArr = new long[sparseArrayY.size()];
        for (int i = 0; i < sparseArrayY.size(); i++) {
            iArr[i] = sparseArrayY.keyAt(i);
            jArr[i] = ((Long) sparseArrayY.valueAt(i)).longValue();
        }
        Bundle bundle = new Bundle();
        bundle.putIntArray("uriSources", iArr);
        bundle.putLongArray("uriTimestamps", jArr);
        o2.p.i(bundle);
    }

    public void C(K1 k1) {
        if (k1 == null) {
            return;
        }
        try {
            b2 b2VarT = c2.t();
            b2VarT.f((U1) this.b);
            b2VarT.e();
            c2.n((c2) b2VarT.b, k1);
            ((K) this.c).M((c2) b2VarT.c());
        } catch (Throwable th) {
            AbstractC3819n0.g("BillingLogger", "Unable to log.", th);
        }
    }

    public void D(M1 m1) {
        if (m1 == null) {
            return;
        }
        try {
            b2 b2VarT = c2.t();
            b2VarT.f((U1) this.b);
            b2VarT.e();
            c2.o((c2) b2VarT.b, m1);
            ((K) this.c).M((c2) b2VarT.c());
        } catch (Throwable th) {
            AbstractC3819n0.g("BillingLogger", "Unable to log.", th);
        }
    }

    public void E(Q1 q1) {
        try {
            b2 b2VarT = c2.t();
            b2VarT.f((U1) this.b);
            b2VarT.e();
            c2.p((c2) b2VarT.b, q1);
            ((K) this.c).M((c2) b2VarT.c());
        } catch (Throwable th) {
            AbstractC3819n0.g("BillingLogger", "Unable to log.", th);
        }
    }

    public void F(f2 f2Var) {
        try {
            K k = (K) this.c;
            b2 b2VarT = c2.t();
            b2VarT.f((U1) this.b);
            b2VarT.e();
            c2.r((c2) b2VarT.b, f2Var);
            k.M((c2) b2VarT.c());
        } catch (Throwable th) {
            AbstractC3819n0.g("BillingLogger", "Unable to log.", th);
        }
    }

    public void G(g2 g2Var) {
        if (g2Var == null) {
            return;
        }
        try {
            b2 b2VarT = c2.t();
            b2VarT.f((U1) this.b);
            b2VarT.e();
            c2.s((c2) b2VarT.b, g2Var);
            ((K) this.c).M((c2) b2VarT.c());
        } catch (Throwable th) {
            AbstractC3819n0.g("BillingLogger", "Unable to log.", th);
        }
    }

    public io.reactivex.rxjava3.internal.operators.completable.a a(io.reactivex.rxjava3.core.p stopToken, Function0 build) {
        Intrinsics.checkNotNullParameter(stopToken, "stopToken");
        Intrinsics.checkNotNullParameter(build, "build");
        io.reactivex.rxjava3.internal.operators.completable.h hVar = new io.reactivex.rxjava3.internal.operators.completable.h(((io.reactivex.rxjava3.core.a) build.invoke()).h((io.reactivex.rxjava3.core.o) this.c), (io.reactivex.rxjava3.core.o) this.b, 0);
        stopToken.getClass();
        io.reactivex.rxjava3.internal.operators.completable.a aVar = new io.reactivex.rxjava3.internal.operators.completable.a(3, hVar, new io.reactivex.rxjava3.internal.operators.completable.c(stopToken, 6));
        Intrinsics.checkNotNullExpressionValue(aVar, "takeUntil(...)");
        return aVar;
    }

    @Override // io.reactivex.rxjava3.functions.h
    public Object apply(Object obj) {
        DBTerm term = (DBTerm) obj;
        Intrinsics.d(term);
        com.quizlet.qutils.data.offline.d payload = ((com.quizlet.quizletandroid.data.management.a) this.c).b;
        com.google.android.datatransport.cct.internal.s sVar = (com.google.android.datatransport.cct.internal.s) this.b;
        Intrinsics.checkNotNullParameter(term, "term");
        Intrinsics.checkNotNullParameter(payload, "payload");
        DBImage definitionImage = term.getDefinitionImage();
        String serverSmallUrl = definitionImage != null ? definitionImage.getServerSmallUrl() : null;
        DBImage definitionImage2 = term.getDefinitionImage();
        int i = 0;
        w wVar = new w(i, new io.reactivex.rxjava3.internal.operators.maybe.j(new io.reactivex.rxjava3.internal.operators.maybe.j(new io.reactivex.rxjava3.internal.operators.maybe.j(sVar.g(payload, term.getDefinitionAudioUrl()), new com.quizlet.data.repository.folderset.c(sVar, payload, term.getWordAudioUrl(), 14), 0), new com.quizlet.data.interactor.folderwithcreator.m(term, serverSmallUrl, definitionImage2 != null ? definitionImage2.getServerMediumUrl() : null, sVar, payload), 0), com.quizlet.quizletandroid.data.management.c.g, 1), Boolean.FALSE);
        Intrinsics.checkNotNullExpressionValue(wVar, "defaultIfEmpty(...)");
        return wVar;
    }

    public o0 b(io.reactivex.rxjava3.core.p stopToken, Function0 build) {
        Intrinsics.checkNotNullParameter(stopToken, "stopToken");
        Intrinsics.checkNotNullParameter(build, "build");
        o0 o0Var = new o0(((io.reactivex.rxjava3.core.i) build.invoke()).w((io.reactivex.rxjava3.core.o) this.c).s((io.reactivex.rxjava3.core.o) this.b), stopToken.m(), 1);
        Intrinsics.checkNotNullExpressionValue(o0Var, "takeUntil(...)");
        return o0Var;
    }

    public w c(io.reactivex.rxjava3.core.p stopToken, Function0 build) {
        Intrinsics.checkNotNullParameter(stopToken, "stopToken");
        Intrinsics.checkNotNullParameter(build, "build");
        io.reactivex.rxjava3.internal.operators.single.k kVarH = ((io.reactivex.rxjava3.core.p) build.invoke()).l((io.reactivex.rxjava3.core.o) this.c).h((io.reactivex.rxjava3.core.o) this.b);
        Objects.requireNonNull(stopToken, "other is null");
        w wVar = new w(4, kVarH, new io.reactivex.rxjava3.internal.operators.flowable.c(stopToken, 2));
        Intrinsics.checkNotNullExpressionValue(wVar, "takeUntil(...)");
        return wVar;
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Enum d(kotlin.coroutines.jvm.internal.c r5) {
        /*
            r4 = this;
            boolean r0 = r5 instanceof com.quizlet.quizletandroid.config.features.properties.e
            if (r0 == 0) goto L13
            r0 = r5
            com.quizlet.quizletandroid.config.features.properties.e r0 = (com.quizlet.quizletandroid.config.features.properties.e) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            com.quizlet.quizletandroid.config.features.properties.e r0 = new com.quizlet.quizletandroid.config.features.properties.e
            r0.<init>(r4, r5)
        L18:
            java.lang.Object r5 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 1
            if (r2 == 0) goto L2f
            if (r2 != r3) goto L27
            androidx.glance.appwidget.protobuf.Z.e(r5)
            goto L47
        L27:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r0)
            throw r5
        L2f:
            androidx.glance.appwidget.protobuf.Z.e(r5)
            com.quizlet.quizletandroid.config.features.properties.d r5 = new com.quizlet.quizletandroid.config.features.properties.d
            r2 = 3
            r5.<init>(r2)
            java.lang.String r2 = ""
            io.reactivex.rxjava3.internal.operators.single.g r5 = r4.o(r5, r2)
            r0.l = r3
            java.lang.Object r5 = com.google.android.gms.internal.mlkit_vision_camera.I1.b(r5, r0)
            if (r5 != r1) goto L47
            return r1
        L47:
            java.lang.String r0 = "await(...)"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r5, r0)
            java.lang.String r5 = (java.lang.String) r5
            com.quizlet.generated.enums.G r0 = com.quizlet.generated.enums.H.Companion
            java.util.Locale r1 = java.util.Locale.ROOT
            java.lang.String r5 = r5.toLowerCase(r1)
            java.lang.String r1 = "toLowerCase(...)"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r5, r1)
            r0.getClass()
            com.quizlet.generated.enums.H r5 = com.quizlet.generated.enums.G.a(r5)
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.work.impl.model.c.d(kotlin.coroutines.jvm.internal.c):java.lang.Enum");
    }

    public ArrayList e(String str) {
        androidx.room.u uVarA = androidx.room.u.a(1, "SELECT work_spec_id FROM dependency WHERE prerequisite_id=?");
        uVarA.g(1, str);
        WorkDatabase_Impl workDatabase_Impl = (WorkDatabase_Impl) this.b;
        workDatabase_Impl.b();
        Cursor cursorN = W1.N(workDatabase_Impl, uVarA, false);
        try {
            ArrayList arrayList = new ArrayList(cursorN.getCount());
            while (cursorN.moveToNext()) {
                arrayList.add(cursorN.getString(0));
            }
            return arrayList;
        } finally {
            cursorN.close();
            uVarA.i();
        }
    }

    @Override // com.facebook.l
    public void f(FacebookException error) {
        Intrinsics.checkNotNullParameter(error, "error");
        ((u0) this.c).invoke(error);
    }

    public H g() {
        String country;
        G g = H.Companion;
        Locale localeB = AbstractC3215n6.i(Resources.getSystem().getConfiguration()).b(0);
        if (localeB == null || (country = localeB.getCountry()) == null) {
            country = "";
        }
        String lowerCase = country.toLowerCase(Locale.ROOT);
        Intrinsics.checkNotNullExpressionValue(lowerCase, "toLowerCase(...)");
        g.getClass();
        return G.a(lowerCase);
    }

    /* JADX WARN: Type inference failed for: r0v5, types: [java.lang.Iterable, java.lang.Object, java.util.List] */
    /* JADX WARN: Type inference failed for: r1v0, types: [java.lang.Object, java.util.List] */
    @Override // androidx.compose.foundation.gestures.snapping.m
    public float h(float f, float f2) {
        float fAbs = Math.abs(f2);
        androidx.compose.foundation.lazy.q qVarH = ((A) this.b).h();
        int i = 0;
        if (!qVarH.j.isEmpty()) {
            ?? r0 = qVarH.j;
            int size = r0.size();
            Iterator it2 = r0.iterator();
            while (it2.hasNext()) {
                i += ((androidx.compose.foundation.lazy.r) it2.next()).p;
            }
            i /= size;
        }
        float f3 = fAbs - i;
        if (f3 < DefinitionKt.NO_Float_VALUE) {
            f3 = 0.0f;
        }
        return Math.signum(f2) * f3;
    }

    @Override // com.facebook.l
    public void i(C result) {
        Intrinsics.checkNotNullParameter(result, "result");
        ((Function1) this.b).invoke(result.a.e);
    }

    /* JADX WARN: Removed duplicated region for block: B:33:0x00ab  */
    /* JADX WARN: Type inference failed for: r2v1, types: [java.lang.Object, java.util.List] */
    @Override // androidx.compose.foundation.gestures.snapping.m
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public float j(float r17) {
        /*
            r16 = this;
            r0 = r16
            java.lang.Object r1 = r0.b
            androidx.compose.foundation.lazy.A r1 = (androidx.compose.foundation.lazy.A) r1
            androidx.compose.foundation.lazy.q r2 = r1.h()
            java.lang.Object r2 = r2.j
            int r3 = r2.size()
            r5 = -8388608(0xffffffffff800000, float:-Infinity)
            r6 = 2139095040(0x7f800000, float:Infinity)
            r8 = r5
            r9 = r6
            r7 = 0
        L17:
            r10 = 0
            if (r7 >= r3) goto L75
            java.lang.Object r11 = r2.get(r7)
            androidx.compose.foundation.lazy.r r11 = (androidx.compose.foundation.lazy.r) r11
            androidx.compose.foundation.lazy.q r12 = r1.h()
            androidx.compose.foundation.gestures.d0 r13 = r12.n
            androidx.compose.foundation.gestures.d0 r14 = androidx.compose.foundation.gestures.EnumC0320d0.a
            if (r13 != r14) goto L36
            long r12 = r12.a()
            r14 = 4294967295(0xffffffff, double:2.1219957905E-314)
            long r12 = r12 & r14
        L34:
            int r12 = (int) r12
            goto L3e
        L36:
            long r12 = r12.a()
            r14 = 32
            long r12 = r12 >> r14
            goto L34
        L3e:
            androidx.compose.foundation.lazy.q r13 = r1.h()
            int r13 = r13.k
            int r13 = -r13
            androidx.compose.foundation.lazy.q r14 = r1.h()
            int r14 = r14.o
            int r15 = r11.p
            int r11 = r11.o
            androidx.compose.foundation.lazy.q r4 = r1.h()
            int r4 = r4.m
            java.lang.Object r4 = r0.c
            androidx.compose.foundation.gestures.snapping.o r4 = (androidx.compose.foundation.gestures.snapping.o) r4
            int r4 = r4.b(r12, r15, r13, r14)
            float r4 = (float) r4
            float r11 = (float) r11
            float r11 = r11 - r4
            int r4 = (r11 > r10 ? 1 : (r11 == r10 ? 0 : -1))
            if (r4 > 0) goto L69
            int r4 = (r11 > r8 ? 1 : (r11 == r8 ? 0 : -1))
            if (r4 <= 0) goto L69
            r8 = r11
        L69:
            int r4 = (r11 > r10 ? 1 : (r11 == r10 ? 0 : -1))
            if (r4 < 0) goto L72
            int r4 = (r11 > r9 ? 1 : (r11 == r9 ? 0 : -1))
            if (r4 >= 0) goto L72
            r9 = r11
        L72:
            int r7 = r7 + 1
            goto L17
        L75:
            androidx.compose.runtime.a0 r1 = r1.f
            androidx.compose.runtime.L0 r1 = (androidx.compose.runtime.L0) r1
            java.lang.Object r1 = r1.getValue()
            androidx.compose.foundation.lazy.q r1 = (androidx.compose.foundation.lazy.q) r1
            androidx.compose.ui.unit.b r1 = r1.h
            float r2 = java.lang.Math.abs(r17)
            float r3 = androidx.compose.foundation.gestures.snapping.l.a
            float r1 = r1.c0(r3)
            int r1 = (r2 > r1 ? 1 : (r2 == r1 ? 0 : -1))
            r2 = 2
            r3 = 1
            if (r1 >= 0) goto L93
            r4 = 0
            goto L9a
        L93:
            int r1 = (r17 > r10 ? 1 : (r17 == r10 ? 0 : -1))
            if (r1 <= 0) goto L99
            r4 = r3
            goto L9a
        L99:
            r4 = r2
        L9a:
            if (r4 != 0) goto La9
            float r1 = java.lang.Math.abs(r9)
            float r2 = java.lang.Math.abs(r8)
            int r1 = (r1 > r2 ? 1 : (r1 == r2 ? 0 : -1))
            if (r1 > 0) goto Lb1
            goto Lab
        La9:
            if (r4 != r3) goto Lad
        Lab:
            r8 = r9
            goto Lb1
        Lad:
            if (r4 != r2) goto Lb0
            goto Lb1
        Lb0:
            r8 = r10
        Lb1:
            int r1 = (r8 > r6 ? 1 : (r8 == r6 ? 0 : -1))
            if (r1 != 0) goto Lb6
            goto Lba
        Lb6:
            int r1 = (r8 > r5 ? 1 : (r8 == r5 ? 0 : -1))
            if (r1 != 0) goto Lbb
        Lba:
            return r10
        Lbb:
            return r8
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.work.impl.model.c.j(float):float");
    }

    public J k() {
        String language;
        I i = J.Companion;
        Locale localeB = AbstractC3215n6.i(Resources.getSystem().getConfiguration()).b(0);
        if (localeB == null || (language = localeB.getLanguage()) == null) {
            language = "";
        }
        String lowerCase = language.toLowerCase(Locale.ROOT);
        Intrinsics.checkNotNullExpressionValue(lowerCase, "toLowerCase(...)");
        i.getClass();
        for (J j : J.values()) {
            if (Intrinsics.b(j.a(), lowerCase)) {
                return j;
            }
        }
        return null;
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object l(java.lang.String r5, kotlin.coroutines.jvm.internal.c r6) {
        /*
            r4 = this;
            boolean r0 = r6 instanceof com.quizlet.remote.model.explanations.a
            if (r0 == 0) goto L13
            r0 = r6
            com.quizlet.remote.model.explanations.a r0 = (com.quizlet.remote.model.explanations.a) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            com.quizlet.remote.model.explanations.a r0 = new com.quizlet.remote.model.explanations.a
            r0.<init>(r4, r6)
        L18:
            java.lang.Object r6 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 1
            if (r2 == 0) goto L2f
            if (r2 != r3) goto L27
            androidx.glance.appwidget.protobuf.Z.e(r6)
            goto L43
        L27:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L2f:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            java.lang.Object r6 = r4.b
            com.quizlet.remote.service.l r6 = (com.quizlet.remote.service.l) r6
            io.reactivex.rxjava3.core.p r5 = r6.b(r5)
            r0.l = r3
            java.lang.Object r6 = com.google.android.gms.internal.mlkit_vision_camera.I1.b(r5, r0)
            if (r6 != r1) goto L43
            return r1
        L43:
            java.lang.String r5 = "await(...)"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r6, r5)
            return r6
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.work.impl.model.c.l(java.lang.String, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Enum m(kotlin.coroutines.jvm.internal.c r5) {
        /*
            r4 = this;
            boolean r0 = r5 instanceof com.quizlet.quizletandroid.config.features.properties.f
            if (r0 == 0) goto L13
            r0 = r5
            com.quizlet.quizletandroid.config.features.properties.f r0 = (com.quizlet.quizletandroid.config.features.properties.f) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            com.quizlet.quizletandroid.config.features.properties.f r0 = new com.quizlet.quizletandroid.config.features.properties.f
            r0.<init>(r4, r5)
        L18:
            java.lang.Object r5 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 1
            if (r2 == 0) goto L2f
            if (r2 != r3) goto L27
            androidx.glance.appwidget.protobuf.Z.e(r5)
            goto L48
        L27:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r0)
            throw r5
        L2f:
            androidx.glance.appwidget.protobuf.Z.e(r5)
            com.quizlet.local.datastore.preferences.c0 r5 = new com.quizlet.local.datastore.preferences.c0
            r2 = 23
            r5.<init>(r2)
            java.lang.String r2 = ""
            io.reactivex.rxjava3.internal.operators.single.g r5 = r4.o(r5, r2)
            r0.l = r3
            java.lang.Object r5 = com.google.android.gms.internal.mlkit_vision_camera.I1.b(r5, r0)
            if (r5 != r1) goto L48
            return r1
        L48:
            java.lang.String r0 = "await(...)"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r5, r0)
            java.lang.String r5 = (java.lang.String) r5
            com.quizlet.generated.enums.G r0 = com.quizlet.generated.enums.H.Companion
            java.util.Locale r1 = java.util.Locale.ROOT
            java.lang.String r5 = r5.toLowerCase(r1)
            java.lang.String r1 = "toLowerCase(...)"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r5, r1)
            r0.getClass()
            com.quizlet.generated.enums.H r5 = com.quizlet.generated.enums.G.a(r5)
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.work.impl.model.c.m(kotlin.coroutines.jvm.internal.c):java.lang.Enum");
    }

    public io.reactivex.rxjava3.internal.operators.single.g n() {
        return o(new C4566c0(28), 0L);
    }

    public io.reactivex.rxjava3.internal.operators.single.g o(Function1 function1, Object obj) {
        C4887f c4887f = (C4887f) this.c;
        c4887f.getClass();
        io.reactivex.rxjava3.internal.operators.single.g gVarG = new io.reactivex.rxjava3.internal.operators.flowable.b(new C4887f(c4887f, 5), 2).g(new androidx.compose.foundation.text.input.internal.u(23, obj, function1));
        Intrinsics.checkNotNullExpressionValue(gVarG, "map(...)");
        return gVarG;
    }

    @Override // com.facebook.l
    public void onCancel() {
    }

    @Override // com.onetrust.otpublishers.headless.Public.OTCallback
    public void onFailure(OTResponse oTResponse) {
        new com.onetrust.otpublishers.headless.Internal.profile.c(((com.onetrust.otpublishers.headless.Internal.Network.d) this.c).a).b();
        ((OTCallback) this.b).onFailure(oTResponse);
    }

    @Override // com.onetrust.otpublishers.headless.Public.OTCallback
    public void onSuccess(OTResponse oTResponse) {
        ((OTCallback) this.b).onSuccess(oTResponse);
    }

    /* JADX WARN: Removed duplicated region for block: B:36:0x00b4  */
    /* JADX WARN: Removed duplicated region for block: B:9:0x0018  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object p(long r6, kotlin.coroutines.jvm.internal.c r8) throws java.lang.Throwable {
        /*
            Method dump skipped, instructions count: 244
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.work.impl.model.c.p(long, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public io.reactivex.rxjava3.internal.operators.single.g q() {
        return o(new com.quizlet.quizletandroid.config.features.properties.d(0), Boolean.TRUE);
    }

    public io.reactivex.rxjava3.internal.operators.single.g r() {
        C4887f c4887f = (C4887f) this.c;
        c4887f.getClass();
        io.reactivex.rxjava3.internal.operators.single.g gVarG = new io.reactivex.rxjava3.internal.operators.flowable.b(new C4887f(c4887f, 5), 2).g(com.quizlet.quizletandroid.config.features.properties.a.j);
        Intrinsics.checkNotNullExpressionValue(gVarG, "map(...)");
        return gVarG;
    }

    public io.reactivex.rxjava3.internal.operators.single.g s() {
        return o(new C4566c0(24), Boolean.FALSE);
    }

    public io.reactivex.rxjava3.internal.operators.single.g t() {
        return o(new C4566c0(21), Boolean.FALSE);
    }

    public io.reactivex.rxjava3.internal.operators.single.g u() {
        return o(new com.quizlet.quizletandroid.config.features.properties.d(2), Boolean.FALSE);
    }

    public void v(Context context, Uri uri) {
        Intent intent = (Intent) this.b;
        intent.setData(uri);
        context.startActivity(intent, (Bundle) this.c);
    }

    public void w(androidx.core.provider.f fVar) {
        int i = fVar.b;
        androidx.core.provider.j jVar = (androidx.core.provider.j) this.c;
        com.airbnb.lottie.network.c cVar = (com.airbnb.lottie.network.c) this.b;
        if (i != 0) {
            jVar.execute(new androidx.core.provider.a(cVar, i, 0));
        } else {
            jVar.execute(new androidx.camera.core.impl.utils.futures.h(4, cVar, fVar.a));
        }
    }

    public void x(long j) {
        ShortcutManager shortcutManager = (ShortcutManager) this.c;
        List<ShortcutInfo> dynamicShortcuts = shortcutManager.getDynamicShortcuts();
        Intrinsics.d(dynamicShortcuts);
        ArrayList arrayList = new ArrayList();
        for (Object obj : dynamicShortcuts) {
            if (Intrinsics.b(((ShortcutInfo) obj).getId(), String.valueOf(j))) {
                arrayList.add(obj);
            }
        }
        ArrayList arrayList2 = new ArrayList(kotlin.collections.C.q(arrayList, 10));
        Iterator it2 = arrayList.iterator();
        while (it2.hasNext()) {
            arrayList2.add(((ShortcutInfo) it2.next()).getId().toString());
        }
        shortcutManager.removeDynamicShortcuts(CollectionsKt.w0(arrayList2));
    }

    public io.reactivex.rxjava3.internal.operators.single.g y() {
        return o(new C4566c0(29), 0);
    }

    public void z(androidx.work.impl.j workSpecId, int i) {
        Intrinsics.checkNotNullParameter(workSpecId, "workSpecId");
        ((androidx.work.impl.utils.taskexecutor.a) this.c).a(new androidx.work.impl.utils.j((C1433e) this.b, workSpecId, false, i));
    }

    public /* synthetic */ c(Object obj, boolean z, Object obj2, int i) {
        this.a = i;
        this.c = obj;
        this.b = obj2;
    }

    @Override // com.google.common.util.concurrent.c
    public void onSuccess(Object obj) throws JSONException {
        D0 d0 = (D0) this.c;
        d0.S();
        B();
        d0.j = false;
        d0.k = 1;
        com.google.android.gms.measurement.internal.I i = ((Y) d0.b).i;
        Y.k(i);
        i.n.g("Successfully registered trigger URI", ((zzov) this.b).a);
        d0.f0();
    }

    public c(Context context, U1 u1) {
        this.a = 7;
        K k = new K();
        try {
            com.google.android.datatransport.runtime.q.b(context);
            k.b = com.google.android.datatransport.runtime.q.a().c(com.google.android.datatransport.cct.a.e).a("PLAY_BILLING_LIBRARY", new com.google.android.datatransport.c("proto"), new com.quizlet.shared.usecase.folderstudymaterials.c(5));
        } catch (Throwable unused) {
            k.a = true;
        }
        this.c = k;
        this.b = u1;
    }

    @Override // com.google.common.util.concurrent.c
    public void onFailure(Throwable th) throws JSONException {
        int i = 1;
        D0 d0 = (D0) this.c;
        d0.S();
        d0.j = false;
        Y y = (Y) d0.b;
        int i2 = 2;
        if (y.g.f0(null, AbstractC3893t.Z0)) {
            String message = th.getMessage();
            d0.o = false;
            if (message != null) {
                if (!(th instanceof IllegalStateException) && !message.contains("garbage collected") && !th.getClass().getSimpleName().equals("ServiceUnavailableException")) {
                    if ((th instanceof SecurityException) && !message.endsWith("READ_DEVICE_CONFIG")) {
                        i2 = 3;
                    }
                } else {
                    if (message.contains("Background")) {
                        d0.o = true;
                    }
                    i2 = 1;
                }
            }
        }
        int i3 = i2 - 1;
        zzov zzovVar = (zzov) this.b;
        com.google.android.gms.measurement.internal.I i4 = y.i;
        if (i3 == 0) {
            Y.k(i4);
            i4.j.h("registerTriggerAsync failed with retriable error. Will try later. App ID, throwable", com.google.android.gms.measurement.internal.I.a0(y.n().X()), com.google.android.gms.measurement.internal.I.a0(th.toString()));
            d0.k = 1;
            d0.r0().add(zzovVar);
            return;
        }
        if (i3 != 1) {
            Y.k(i4);
            i4.g.h("registerTriggerAsync failed. Dropping URI. App ID, Throwable", com.google.android.gms.measurement.internal.I.a0(y.n().X()), th);
            B();
            d0.k = 1;
            d0.f0();
            return;
        }
        d0.r0().add(zzovVar);
        if (d0.k > ((Integer) AbstractC3893t.v0.a(null)).intValue()) {
            d0.k = 1;
            Y.k(i4);
            i4.j.h("registerTriggerAsync failed. May try later. App ID, throwable", com.google.android.gms.measurement.internal.I.a0(y.n().X()), com.google.android.gms.measurement.internal.I.a0(th.toString()));
            return;
        }
        Y.k(i4);
        i4.j.i("registerTriggerAsync failed. App ID, delay in seconds, throwable", com.google.android.gms.measurement.internal.I.a0(y.n().X()), com.google.android.gms.measurement.internal.I.a0(String.valueOf(d0.k)), com.google.android.gms.measurement.internal.I.a0(th.toString()));
        int i5 = d0.k;
        if (d0.l == null) {
            d0.l = new C3902x0(d0, y, i);
        }
        d0.l.c(i5 * 1000);
        int i6 = d0.k;
        d0.k = i6 + i6;
    }

    public c(Q q, l lVar) {
        this.a = 12;
        this.c = lVar;
        ((C3008j0) q.a).a(new com.google.firebase.analytics.connector.internal.b(this, 0));
        this.b = new HashSet();
    }

    public c(GoogleApiAvailability googleApiAvailability) {
        this.a = 10;
        this.b = new SparseIntArray();
        com.google.android.gms.common.internal.u.h(googleApiAvailability);
        this.c = googleApiAvailability;
    }

    public c(com.quizlet.local.ormlite.models.bookmark.a folderLocalDataStore, com.quizlet.remote.model.folder.p folderRemoteDataStore) {
        this.a = 19;
        Intrinsics.checkNotNullParameter(folderLocalDataStore, "folderLocalDataStore");
        Intrinsics.checkNotNullParameter(folderRemoteDataStore, "folderRemoteDataStore");
        this.b = folderLocalDataStore;
        this.c = folderRemoteDataStore;
    }

    public c(io.reactivex.rxjava3.core.o uiScheduler, io.reactivex.rxjava3.core.o backgroundScheduler) {
        this.a = 15;
        Intrinsics.checkNotNullParameter(uiScheduler, "uiScheduler");
        Intrinsics.checkNotNullParameter(backgroundScheduler, "backgroundScheduler");
        this.b = uiScheduler;
        this.c = backgroundScheduler;
    }

    public c(com.quizlet.data.repository.studysetwithcreatorinclass.g repository, c dispatcher) {
        this.a = 18;
        Intrinsics.checkNotNullParameter(repository, "repository");
        Intrinsics.checkNotNullParameter(dispatcher, "dispatcher");
        this.b = repository;
        this.c = dispatcher;
    }

    public c(l signUpRequestParentEmailFeature, com.quizlet.login.common.util.b ageUtil, com.quizlet.time.b timeUtils) {
        this.a = 24;
        Intrinsics.checkNotNullParameter(signUpRequestParentEmailFeature, "signUpRequestParentEmailFeature");
        Intrinsics.checkNotNullParameter(ageUtil, "ageUtil");
        Intrinsics.checkNotNullParameter(timeUtils, "timeUtils");
        this.b = signUpRequestParentEmailFeature;
        this.c = ageUtil;
    }

    public c(UserInfoCache userInfoCache, com.quizlet.utmhelper.c utmParamsHelper) {
        this.a = 21;
        Intrinsics.checkNotNullParameter(userInfoCache, "userInfoCache");
        Intrinsics.checkNotNullParameter(utmParamsHelper, "utmParamsHelper");
        this.b = userInfoCache;
        this.c = utmParamsHelper;
    }

    public c(com.quizlet.data.repository.folderwithcreator.e repository, AbstractC5040y ioDispatcher) {
        this.a = 17;
        Intrinsics.checkNotNullParameter(ioDispatcher, "ioDispatcher");
        Intrinsics.checkNotNullParameter(repository, "repository");
        this.b = ioDispatcher;
        this.c = repository;
    }

    public c(com.quizlet.local.ormlite.models.bookmark.a classFolderLocal, com.quizlet.local.ormlite.models.bookmark.a folderWithCreatorLocal) {
        this.a = 23;
        Intrinsics.checkNotNullParameter(classFolderLocal, "classFolderLocal");
        Intrinsics.checkNotNullParameter(folderWithCreatorLocal, "folderWithCreatorLocal");
        this.b = classFolderLocal;
        this.c = folderWithCreatorLocal;
    }

    public c(com.quizlet.data.repository.folder.i folderRepository, AbstractC5040y ioDispatcher) {
        this.a = 16;
        Intrinsics.checkNotNullParameter(folderRepository, "folderRepository");
        Intrinsics.checkNotNullParameter(ioDispatcher, "ioDispatcher");
        this.b = folderRepository;
        this.c = ioDispatcher;
    }

    public c(com.quizlet.remote.service.l rxService, com.quizlet.remote.service.p meteringService) {
        this.a = 29;
        Intrinsics.checkNotNullParameter(rxService, "rxService");
        Intrinsics.checkNotNullParameter(meteringService, "meteringService");
        this.b = rxService;
        this.c = meteringService;
    }

    public c(c getStudySetsWithCreatorInClassUseCase, com.quizlet.data.repository.folderwithcreator.e getFoldersWithCreatorInClassUseCase) {
        this.a = 27;
        Intrinsics.checkNotNullParameter(getStudySetsWithCreatorInClassUseCase, "getStudySetsWithCreatorInClassUseCase");
        Intrinsics.checkNotNullParameter(getFoldersWithCreatorInClassUseCase, "getFoldersWithCreatorInClassUseCase");
        this.b = getStudySetsWithCreatorInClassUseCase;
        this.c = getFoldersWithCreatorInClassUseCase;
    }

    public c(Context appContext, ShortcutManager shortcutManager) {
        this.a = 28;
        Intrinsics.checkNotNullParameter(appContext, "appContext");
        Intrinsics.checkNotNullParameter(shortcutManager, "shortcutManager");
        this.b = appContext;
        this.c = shortcutManager;
    }

    public c(com.quizlet.infra.legacysyncengine.managers.d loggedInUserManager, com.quizlet.billing.subscriptions.i mSubscriptionLookup) {
        this.a = 25;
        Intrinsics.checkNotNullParameter(loggedInUserManager, "loggedInUserManager");
        Intrinsics.checkNotNullParameter(mSubscriptionLookup, "mSubscriptionLookup");
        this.b = mSubscriptionLookup;
        io.reactivex.rxjava3.subjects.d dVar = loggedInUserManager.l;
        dVar.getClass();
        C4887f c4887f = new C4887f(dVar, 1);
        Intrinsics.checkNotNullExpressionValue(c4887f, "getLoggedInUserObservable(...)");
        this.c = c4887f;
    }

    public c(Function1 success, u0 error) {
        this.a = 20;
        Intrinsics.checkNotNullParameter(success, "success");
        Intrinsics.checkNotNullParameter(error, "error");
        this.b = success;
        this.c = error;
    }

    public c(WorkDatabase_Impl database) {
        this.a = 0;
        this.b = database;
        Intrinsics.checkNotNullParameter(database, "database");
        this.c = new b(database, 0);
    }

    public c(String str) {
        this.a = 2;
        this.b = (ExtraSupportedOutputSizeQuirk) androidx.camera.camera2.internal.compat.quirk.b.a.b(ExtraSupportedOutputSizeQuirk.class);
        this.c = new androidx.camera.camera2.internal.compat.workaround.b(str);
    }

    public c(C1433e processor, androidx.work.impl.utils.taskexecutor.a workTaskExecutor) {
        this.a = 6;
        Intrinsics.checkNotNullParameter(processor, "processor");
        Intrinsics.checkNotNullParameter(workTaskExecutor, "workTaskExecutor");
        this.b = processor;
        this.c = workTaskExecutor;
    }

    public c(com.google.firebase.messaging.p pVar) {
        this.a = 13;
        this.b = pVar.q("gcm.n.title");
        pVar.n("gcm.n.title");
        Object[] objArrM = pVar.m("gcm.n.title");
        if (objArrM != null) {
            String[] strArr = new String[objArrM.length];
            for (int i = 0; i < objArrM.length; i++) {
                strArr[i] = String.valueOf(objArrM[i]);
            }
        }
        this.c = pVar.q("gcm.n.body");
        pVar.n("gcm.n.body");
        Object[] objArrM2 = pVar.m("gcm.n.body");
        if (objArrM2 != null) {
            String[] strArr2 = new String[objArrM2.length];
            for (int i2 = 0; i2 < objArrM2.length; i2++) {
                strArr2[i2] = String.valueOf(objArrM2[i2]);
            }
        }
        pVar.q("gcm.n.icon");
        if (TextUtils.isEmpty(pVar.q("gcm.n.sound2"))) {
            pVar.q("gcm.n.sound");
        }
        pVar.q("gcm.n.tag");
        pVar.q("gcm.n.color");
        pVar.q("gcm.n.click_action");
        pVar.q("gcm.n.android_channel_id");
        String strQ = pVar.q("gcm.n.link_android");
        strQ = TextUtils.isEmpty(strQ) ? pVar.q("gcm.n.link") : strQ;
        if (!TextUtils.isEmpty(strQ)) {
            Uri.parse(strQ);
        }
        pVar.q("gcm.n.image");
        pVar.q("gcm.n.ticker");
        pVar.j("gcm.n.notification_priority");
        pVar.j("gcm.n.visibility");
        pVar.j("gcm.n.notification_count");
        pVar.h("gcm.n.sticky");
        pVar.h("gcm.n.local_only");
        pVar.h("gcm.n.default_sound");
        pVar.h("gcm.n.default_vibrate_timings");
        pVar.h("gcm.n.default_light_settings");
        pVar.o();
        pVar.l();
        pVar.r();
    }
}
