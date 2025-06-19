package com.quizlet.billing.manager;

import androidx.appcompat.app.L;
import androidx.appcompat.app.Q;
import com.android.billingclient.api.C1473b;
import com.android.billingclient.api.l;
import com.android.billingclient.api.m;
import com.google.android.gms.internal.play_billing.B;
import com.google.firebase.crashlytics.internal.common.j;
import io.reactivex.rxjava3.core.p;
import io.reactivex.rxjava3.subjects.r;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final /* synthetic */ class e implements io.reactivex.rxjava3.functions.d {
    public final /* synthetic */ int a;
    public final /* synthetic */ f b;

    public /* synthetic */ e(f fVar, int i) {
        this.a = i;
        this.b = fVar;
    }

    @Override // io.reactivex.rxjava3.functions.d
    public final void accept(Object obj) {
        switch (this.a) {
            case 0:
                int iIntValue = ((Number) obj).intValue();
                f fVar = this.b;
                if (iIntValue != 0) {
                    fVar.getClass();
                    if (iIntValue != 3) {
                        timber.log.c.a.e(new BillingLibraryException(iIntValue, android.support.v4.media.session.a.f(iIntValue, "Can't update inventory, setup completed with error = ")));
                        return;
                    } else {
                        timber.log.c.a.o("Billing unavailable with updating inventory", new Object[0]);
                        return;
                    }
                }
                com.quizlet.billing.model.a aVar = fVar.d;
                aVar.c.clear();
                aVar.a.clear();
                r rVar = new r();
                Intrinsics.checkNotNullExpressionValue(rVar, "create(...)");
                androidx.sqlite.db.a aVar2 = new androidx.sqlite.db.a();
                aVar2.b = "subs";
                m mVar = new m(aVar2);
                Intrinsics.checkNotNullExpressionValue(mVar, "build(...)");
                C1473b c1473b = fVar.e;
                if (c1473b == null) {
                    Intrinsics.m("billingClient");
                    throw null;
                }
                c1473b.g(mVar, new a(fVar, rVar, 0));
                r rVar2 = new r();
                Intrinsics.checkNotNullExpressionValue(rVar2, "create(...)");
                String[] strArr = f.l;
                ArrayList arrayList = new ArrayList(20);
                for (int i = 0; i < 20; i++) {
                    String str = strArr[i];
                    androidx.emoji2.text.r rVar3 = new androidx.emoji2.text.r();
                    rVar3.a = str;
                    if (str == null) {
                        throw new IllegalArgumentException("Product id must be provided.");
                    }
                    arrayList.add(new l(rVar3));
                }
                L l = new L(16);
                if (arrayList.isEmpty()) {
                    throw new IllegalArgumentException("Product list cannot be empty.");
                }
                HashSet hashSet = new HashSet();
                Iterator it2 = arrayList.iterator();
                while (it2.hasNext()) {
                    ((l) it2.next()).getClass();
                    hashSet.add("subs");
                }
                if (hashSet.size() > 1) {
                    throw new IllegalArgumentException("All products should be of the same product type.");
                }
                B bN = B.n(arrayList);
                l.b = bN;
                if (bN == null) {
                    throw new IllegalArgumentException("Product list must be set to a non empty list.");
                }
                Q q = new Q();
                q.a = (B) l.b;
                Intrinsics.checkNotNullExpressionValue(q, "build(...)");
                C1473b c1473b2 = fVar.e;
                if (c1473b2 == null) {
                    Intrinsics.m("billingClient");
                    throw null;
                }
                c1473b2.f(q, new a(fVar, rVar2, 1));
                p.p(rVar, rVar2, new j(fVar, 4)).l(io.reactivex.rxjava3.schedulers.e.c).h(io.reactivex.rxjava3.android.schedulers.b.a()).i(new e(fVar, 1), new d(timber.log.c.a, 1));
                return;
            default:
                com.quizlet.billing.model.a p0 = (com.quizlet.billing.model.a) obj;
                Intrinsics.checkNotNullParameter(p0, "p0");
                f fVar2 = this.b;
                if (fVar2.g.s() || fVar2.g.r()) {
                    fVar2.g = new r();
                }
                fVar2.g.onSuccess(p0);
                return;
        }
    }
}
