package com.google.android.gms.internal.ads;

import android.webkit.WebView;
import androidx.camera.camera2.internal.RunnableC0133j;
import androidx.camera.camera2.internal.j0;
import com.google.android.gms.ads.nonagon.signalgeneration.AbstractC1642h;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3116c6;
import com.quizlet.db.data.models.persisted.DBStudySet;
import com.quizlet.quizletandroid.R;
import com.quizlet.uicommon.ui.common.dialogs.e;
import java.util.Collections;
import java.util.HashSet;
import java.util.UUID;
import kotlin.jvm.functions.Function1;

/* renamed from: com.google.android.gms.internal.ads.qm, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final /* synthetic */ class C2537qm implements io.reactivex.rxjava3.functions.h {
    public Object a;
    public int b;
    public int c;
    public final Object d;
    public final Object e;
    public Object f;
    public final Object g;

    public /* synthetic */ C2537qm(String str, String str2, String str3, int i, WebView webView, String str4, int i2) {
        this.a = str;
        this.d = str2;
        this.e = str3;
        this.b = i;
        this.g = webView;
        this.f = str4;
        this.c = i2;
    }

    public void a(com.google.firebase.components.j jVar) {
        if (((HashSet) this.d).contains(jVar.a)) {
            throw new IllegalArgumentException("Components are not allowed to depend on interfaces they themselves provide.");
        }
        ((HashSet) this.e).add(jVar);
    }

    @Override // io.reactivex.rxjava3.functions.h
    public Object apply(Object obj) {
        com.quizlet.features.setpage.usecases.g gVar = (com.quizlet.features.setpage.usecases.g) obj;
        int i = gVar == null ? -1 : com.quizlet.features.setpage.utils.setpermissions.d.a[gVar.ordinal()];
        Function1 function1 = (Function1) this.a;
        if (i == 1) {
            return new io.reactivex.rxjava3.internal.operators.completable.c(new com.appsflyer.a(1, function1), 5);
        }
        final com.quizlet.baseui.base.b bVar = (com.quizlet.baseui.base.b) this.e;
        if (i != 2) {
            return new io.reactivex.rxjava3.internal.operators.completable.c(new RunnableC0133j(bVar, this.c, 6), 5);
        }
        final com.appsflyer.a aVar = new com.appsflyer.a(2, function1);
        final DBStudySet dBStudySet = (DBStudySet) this.f;
        final com.quizlet.features.setpage.utils.setpermissions.f fVar = (com.quizlet.features.setpage.utils.setpermissions.f) this.d;
        final int i2 = this.b;
        final com.google.firebase.crashlytics.internal.metadata.q qVar = (com.google.firebase.crashlytics.internal.metadata.q) this.g;
        return new io.reactivex.rxjava3.internal.operators.completable.c(new Runnable() { // from class: com.quizlet.features.setpage.utils.setpermissions.c
            @Override // java.lang.Runnable
            public final void run() {
                f fVar2 = fVar;
                boolean zB = fVar2.a.b();
                com.quizlet.baseui.base.b bVar2 = bVar;
                if (!zB) {
                    if (bVar2.isFinishing()) {
                        return;
                    }
                    AbstractC3116c6.h(R.string.log_in_to_view_set, bVar2.getSupportFragmentManager());
                    return;
                }
                e.a aVar2 = new e.a(bVar2);
                aVar2.c(i2);
                aVar2.a(new com.quizlet.uicommon.ui.common.dialogs.d(aVar2.a.getString(R.string.set_password_hint), 2), new b(bVar2));
                aVar2.f(R.string.set_protected);
                aVar2.e(R.string.OK, new j0(fVar2, bVar2, dBStudySet, aVar));
                aVar2.d(R.string.cancel_dialog_button, new com.google.android.material.search.a(qVar, 22));
                aVar2.b().show();
            }
        }, 5);
    }

    public com.google.firebase.components.a b() {
        if (((com.google.firebase.components.d) this.f) != null) {
            return new com.google.firebase.components.a((String) this.a, new HashSet((HashSet) this.d), new HashSet((HashSet) this.e), this.b, this.c, (com.google.firebase.components.d) this.f, (HashSet) this.g);
        }
        throw new IllegalStateException("Missing required property: factory.");
    }

    public void c(int i) {
        if (!(this.b == 0)) {
            throw new IllegalStateException("Instantiation type has already been set.");
        }
        this.b = i;
    }

    public Object d() {
        A7 a7A = A7.a((String) this.a, (String) this.d);
        Mr mrO = C2147hi.o("javascript");
        String str = (String) this.e;
        Mr mrO2 = C2147hi.o(str);
        int i = this.b;
        Ir irM = C2147hi.m(AbstractC1642h.c(i));
        Mr mr = Mr.NONE;
        if (mrO == mr) {
            com.google.android.gms.ads.internal.util.client.i.h("Omid js session error; Unable to parse impression owner: javascript");
            return null;
        }
        if (irM == null) {
            com.google.android.gms.ads.internal.util.client.i.h("Omid js session error; Unable to parse creative type: ".concat(AbstractC1642h.B(i)));
            return null;
        }
        if (irM == Ir.VIDEO && mrO2 == mr) {
            com.google.android.gms.ads.internal.util.client.i.h("Omid js session error; Video events owner unknown for video creative: ".concat(String.valueOf(str)));
            return null;
        }
        C2210j2 c2210j2 = new C2210j2(a7A, (WebView) this.g, (String) this.f, "", Gr.JAVASCRIPT);
        Bs bsA = Bs.a(irM, C2147hi.n(AbstractC1642h.d(this.c)), mrO, mrO2, true);
        if (AbstractC1972di.M.b) {
            return new C2665tm(new Hr(bsA, c2210j2, UUID.randomUUID().toString()), c2210j2);
        }
        throw new IllegalStateException("Method called before OM SDK activation");
    }

    public C2537qm(Function1 function1, com.quizlet.features.setpage.utils.setpermissions.f fVar, com.quizlet.baseui.base.b bVar, DBStudySet dBStudySet, int i, com.google.firebase.crashlytics.internal.metadata.q qVar, int i2) {
        this.a = function1;
        this.d = fVar;
        this.e = bVar;
        this.f = dBStudySet;
        this.b = i;
        this.g = qVar;
        this.c = i2;
    }

    public C2537qm(Class cls, Class[] clsArr) {
        this.a = null;
        HashSet hashSet = new HashSet();
        this.d = hashSet;
        this.e = new HashSet();
        this.b = 0;
        this.c = 0;
        this.g = new HashSet();
        hashSet.add(com.google.firebase.components.q.a(cls));
        for (Class cls2 : clsArr) {
            com.google.android.gms.internal.mlkit_vision_common.y4.b(cls2, "Null interface");
            ((HashSet) this.d).add(com.google.firebase.components.q.a(cls2));
        }
    }

    public C2537qm(com.google.firebase.components.q qVar, com.google.firebase.components.q[] qVarArr) {
        this.a = null;
        HashSet hashSet = new HashSet();
        this.d = hashSet;
        this.e = new HashSet();
        this.b = 0;
        this.c = 0;
        this.g = new HashSet();
        hashSet.add(qVar);
        for (com.google.firebase.components.q qVar2 : qVarArr) {
            com.google.android.gms.internal.mlkit_vision_common.y4.b(qVar2, "Null interface");
        }
        Collections.addAll((HashSet) this.d, qVarArr);
    }
}
