package com.quizlet.data.repository.user;

import android.util.SparseArray;
import android.util.SparseIntArray;
import androidx.compose.animation.d0;
import androidx.navigation.internal.m;
import androidx.recyclerview.widget.R0;
import androidx.recyclerview.widget.X;
import com.android.billingclient.api.s;
import com.google.android.gms.ads.internal.j;
import com.google.android.gms.ads.internal.util.F;
import com.google.android.gms.internal.ads.AbstractC2346m9;
import com.google.android.gms.internal.ads.Am;
import com.google.android.gms.internal.ads.C1849aq;
import com.google.android.gms.internal.ads.C1920ca;
import com.google.android.gms.internal.ads.C2310la;
import com.google.android.gms.internal.ads.C2313ld;
import com.google.android.gms.internal.ads.C2752vn;
import com.google.android.gms.internal.ads.C2880ym;
import com.google.android.gms.internal.ads.Gq;
import com.google.android.gms.internal.ads.HF;
import com.google.android.gms.internal.ads.InterfaceC2051fa;
import com.google.android.gms.internal.ads.InterfaceC2183ia;
import com.google.android.gms.internal.ads.InterfaceC2399nd;
import com.google.android.gms.internal.ads.Vp;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3633h4;
import com.quizlet.db.data.models.persisted.DBStudySet;
import com.quizlet.features.infra.basestudy.manager.f;
import com.quizlet.features.match.data.I;
import com.quizlet.generated.enums.G1;
import com.quizlet.quizletandroid.R;
import io.reactivex.rxjava3.core.i;
import io.reactivex.rxjava3.core.o;
import io.reactivex.rxjava3.core.p;
import io.reactivex.rxjava3.functions.h;
import io.reactivex.rxjava3.internal.operators.observable.J;
import io.reactivex.rxjava3.internal.operators.observable.r;
import io.reactivex.rxjava3.internal.operators.single.g;
import java.util.UUID;
import kotlin.collections.A;
import kotlin.collections.C4933y;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.AbstractC5040y;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final class e implements R0, InterfaceC2399nd, Gq, h {
    public final /* synthetic */ int a;
    public Object b;
    public Object c;
    public Object d;
    public Object e;

    public e() {
        this.a = 5;
        this.b = new m();
    }

    @Override // androidx.recyclerview.widget.R0
    public int a(int i) {
        SparseIntArray sparseIntArray = (SparseIntArray) this.c;
        int iIndexOfKey = sparseIntArray.indexOfKey(i);
        if (iIndexOfKey >= 0) {
            return sparseIntArray.valueAt(iIndexOfKey);
        }
        StringBuilder sbV = android.support.v4.media.session.a.v(i, "requested global type ", " does not belong to the adapter:");
        sbV.append(((X) this.d).c);
        throw new IllegalStateException(sbV.toString());
    }

    @Override // io.reactivex.rxjava3.functions.h
    public Object apply(Object obj) {
        com.quizlet.features.infra.basestudy.data.models.shareset.a status = (com.quizlet.features.infra.basestudy.data.models.shareset.a) obj;
        Intrinsics.checkNotNullParameter(status, "status");
        com.quizlet.features.infra.basestudy.data.models.shareset.a aVar = com.quizlet.features.infra.basestudy.data.models.shareset.a.d;
        com.quizlet.quizletandroid.ui.studymodes.match.managers.a aVar2 = (com.quizlet.quizletandroid.ui.studymodes.match.managers.a) this.b;
        if (status != aVar) {
            aVar2.getClass();
            io.reactivex.rxjava3.internal.operators.flowable.b s1 = p.f(status);
            Intrinsics.checkNotNullExpressionValue(s1, "just(...)");
            p s2 = aVar2.c.m(-1L);
            Intrinsics.checkNotNullParameter(s1, "s1");
            Intrinsics.checkNotNullParameter(s2, "s2");
            p pVarP = p.p(s1, s2, io.reactivex.rxjava3.kotlin.a.d);
            Intrinsics.checkNotNullExpressionValue(pVarP, "Single.zip(s1, s2, BiFun…n { t, u -> Pair(t, u) })");
            g gVarG = pVarP.g(new com.quizlet.data.repository.folderset.c(aVar2, (String) this.d, (String) this.e, 16));
            Intrinsics.checkNotNullExpressionValue(gVarG, "map(...)");
            return gVarG;
        }
        int accessType = ((DBStudySet) this.c).getAccessType();
        f fVar = aVar2.a;
        com.quizlet.features.infra.snackbar.m mVar = null;
        Integer numValueOf = !(fVar.v == G1.SET && (fVar.u > 0L ? 1 : (fVar.u == 0L ? 0 : -1)) > 0) ? Integer.valueOf(R.string.cannot_complete_action) : accessType != 2 ? Integer.valueOf(R.string.cannot_share_private_set) : null;
        if (numValueOf != null) {
            int iIntValue = numValueOf.intValue();
            Object[] args = new Object[0];
            Intrinsics.checkNotNullParameter(args, "args");
            mVar = new com.quizlet.features.infra.snackbar.m(new com.quizlet.qutils.string.f(iIntValue, C4933y.P(args)));
        }
        io.reactivex.rxjava3.internal.operators.flowable.b bVarF = p.f(new I(mVar));
        Intrinsics.checkNotNullExpressionValue(bVarF, "just(...)");
        return bVarF;
    }

    @Override // com.google.android.gms.internal.ads.Gq
    public Object b(Object obj) {
        return ((Am) ((C2752vn) this.b).e).b((C1849aq) this.c, (Vp) this.d, (C2880ym) this.e);
    }

    @Override // androidx.recyclerview.widget.R0
    public int c(int i) {
        SparseIntArray sparseIntArray = (SparseIntArray) this.b;
        int iIndexOfKey = sparseIntArray.indexOfKey(i);
        if (iIndexOfKey > -1) {
            return sparseIntArray.valueAt(iIndexOfKey);
        }
        s sVar = (s) this.e;
        int i2 = sVar.b;
        sVar.b = i2 + 1;
        ((SparseArray) sVar.c).put(i2, (X) this.d);
        sparseIntArray.put(i, i2);
        ((SparseIntArray) this.c).put(i2, i);
        return i2;
    }

    public String d() {
        String str = (String) this.e;
        return str != null ? str : "activate";
    }

    @Override // androidx.recyclerview.widget.R0
    public void dispose() {
        SparseArray sparseArray = (SparseArray) ((s) this.e).c;
        for (int size = sparseArray.size() - 1; size >= 0; size--) {
            if (((X) sparseArray.valueAt(size)) == ((X) this.d)) {
                sparseArray.removeAt(size);
            }
        }
    }

    public r e(long j) {
        com.quizlet.local.ormlite.models.bookmark.a aVar = (com.quizlet.local.ormlite.models.bookmark.a) ((com.quizlet.data.repository.explanations.myexplanations.a) this.b).b;
        Long id = Long.valueOf(Long.valueOf(j).longValue());
        Intrinsics.checkNotNullParameter(id, "id");
        p pVarB = aVar.b(A.b(id));
        Intrinsics.checkNotNullParameter(pVarB, "<this>");
        g gVarG = pVarB.g(com.quizlet.data.ext.a.d);
        Intrinsics.checkNotNullExpressionValue(gVarG, "map(...)");
        J j2 = new J(gVarG.m(), new com.google.mlkit.vision.documentscanner.internal.c(this, 13), 4);
        Intrinsics.checkNotNullExpressionValue(j2, "onErrorResumeNext(...)");
        J j3 = new J(new com.jakewharton.rxbinding4.a(new com.quizlet.data.repository.folderwithcreatorinclass.b(this, j, 4), 4), new com.google.firebase.crashlytics.internal.settings.b(this, 16), 4);
        Intrinsics.checkNotNullExpressionValue(j3, "onErrorResumeNext(...)");
        r rVarG = i.g(j2, j3);
        Intrinsics.checkNotNullExpressionValue(rVarG, "concat(...)");
        return rVarG;
    }

    /* JADX WARN: Removed duplicated region for block: B:8:0x0014  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object f(java.lang.String r11, java.lang.String r12, java.lang.Integer r13, int r14, kotlin.coroutines.jvm.internal.c r15) throws java.lang.Throwable {
        /*
            r10 = this;
            boolean r2 = r15 instanceof com.quizlet.data.repository.user.c
            if (r2 == 0) goto L14
            r2 = r15
            com.quizlet.data.repository.user.c r2 = (com.quizlet.data.repository.user.c) r2
            int r3 = r2.l
            r4 = -2147483648(0xffffffff80000000, float:-0.0)
            r5 = r3 & r4
            if (r5 == 0) goto L14
            int r3 = r3 - r4
            r2.l = r3
        L12:
            r7 = r2
            goto L1a
        L14:
            com.quizlet.data.repository.user.c r2 = new com.quizlet.data.repository.user.c
            r2.<init>(r10, r15)
            goto L12
        L1a:
            java.lang.Object r0 = r7.j
            kotlin.coroutines.intrinsics.a r8 = kotlin.coroutines.intrinsics.a.a
            int r2 = r7.l
            r9 = 1
            if (r2 == 0) goto L31
            if (r2 != r9) goto L29
            androidx.glance.appwidget.protobuf.Z.e(r0)
            goto L4c
        L29:
            java.lang.IllegalStateException r0 = new java.lang.IllegalStateException
            java.lang.String r2 = "call to 'resume' before 'invoke' with coroutine"
            r0.<init>(r2)
            throw r0
        L31:
            androidx.glance.appwidget.protobuf.Z.e(r0)
            com.quizlet.data.repository.user.d r0 = new com.quizlet.data.repository.user.d
            r6 = 0
            r1 = r10
            r2 = r11
            r3 = r12
            r4 = r13
            r5 = r14
            r0.<init>(r1, r2, r3, r4, r5, r6)
            r7.l = r9
            java.lang.Object r2 = r10.e
            kotlinx.coroutines.y r2 = (kotlinx.coroutines.AbstractC5040y) r2
            java.lang.Object r0 = kotlinx.coroutines.E.J(r2, r0, r7)
            if (r0 != r8) goto L4c
            return r8
        L4c:
            java.lang.String r2 = "withContext(...)"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r0, r2)
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.repository.user.e.f(java.lang.String, java.lang.String, java.lang.Integer, int, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public String toString() {
        switch (this.a) {
            case 5:
                StringBuilder sb = new StringBuilder("LinkProperty{linkTextProperty=");
                AbstractC3633h4.a((m) this.b, sb, "url=");
                sb.append((String) this.c);
                sb.append("actionDescription=");
                return d0.r(sb, (String) this.e, '}');
            default:
                return super.toString();
        }
    }

    public e(com.google.android.gms.ads.internal.c cVar, C1920ca c1920ca, Object obj, C2313ld c2313ld) {
        this.a = 2;
        this.b = c1920ca;
        this.c = obj;
        this.d = c2313ld;
        this.e = cVar;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2399nd
    /* renamed from: b */
    public void mo21b(Object obj) throws JSONException {
        InterfaceC2051fa interfaceC2051fa = (InterfaceC2051fa) obj;
        com.google.android.gms.ads.internal.util.A.l("callJs > getEngine: Promise fulfilled");
        Object obj2 = this.c;
        C2313ld c2313ld = (C2313ld) this.d;
        com.google.android.gms.ads.internal.c cVar = (com.google.android.gms.ads.internal.c) this.e;
        C1920ca c1920ca = (C1920ca) this.b;
        try {
            F f = j.C.c;
            String string = UUID.randomUUID().toString();
            AbstractC2346m9.o.a(string, new C2310la(cVar, c1920ca, c2313ld));
            JSONObject jSONObject = new JSONObject();
            jSONObject.put("id", string);
            jSONObject.put("args", ((InterfaceC2183ia) cVar.c).c(obj2));
            interfaceC2051fa.d((String) cVar.e, jSONObject);
        } catch (Exception e) {
            try {
                c2313ld.d(e);
                com.google.android.gms.ads.internal.util.client.i.f("Unable to invokeJavascript", e);
            } finally {
                c1920ca.v();
            }
        }
    }

    public e(HF hf, boolean[] zArr) {
        this.a = 4;
        this.b = hf;
        this.c = zArr;
        int i = hf.a;
        this.d = new boolean[i];
        this.e = new boolean[i];
    }

    public /* synthetic */ e(Object obj, Object obj2, Object obj3, Object obj4, int i) {
        this.a = i;
        this.b = obj;
        this.c = obj2;
        this.d = obj3;
        this.e = obj4;
    }

    public e(com.quizlet.features.infra.studysetting.datasource.a answerDataSource, com.quizlet.features.infra.studysetting.datasource.a termDataSource, com.quizlet.data.repository.explanations.exercise.b progressResetDataProvider, com.quizlet.shared.usecase.folderstudymaterials.c mapper, o scheduler) {
        this.a = 6;
        Intrinsics.checkNotNullParameter(answerDataSource, "answerDataSource");
        Intrinsics.checkNotNullParameter(termDataSource, "termDataSource");
        Intrinsics.checkNotNullParameter(progressResetDataProvider, "progressResetDataProvider");
        Intrinsics.checkNotNullParameter(mapper, "mapper");
        Intrinsics.checkNotNullParameter(scheduler, "scheduler");
        this.b = answerDataSource;
        this.c = termDataSource;
        this.d = progressResetDataProvider;
        this.e = mapper;
    }

    public e(com.quizlet.data.repository.explanations.myexplanations.a factory, com.quizlet.data.connectivity.a networkStatus, org.slf4j.b logger, AbstractC5040y dispatcher) {
        this.a = 0;
        Intrinsics.checkNotNullParameter(factory, "factory");
        Intrinsics.checkNotNullParameter(networkStatus, "networkStatus");
        Intrinsics.checkNotNullParameter(logger, "logger");
        Intrinsics.checkNotNullParameter(dispatcher, "dispatcher");
        this.b = factory;
        this.c = networkStatus;
        this.d = logger;
        this.e = dispatcher;
    }

    public e(s sVar, X x) {
        this.a = 1;
        this.e = sVar;
        this.b = new SparseIntArray(1);
        this.c = new SparseIntArray(1);
        this.d = x;
    }
}
