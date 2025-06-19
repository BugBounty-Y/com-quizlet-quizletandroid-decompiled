package com.quizlet.billing.subscriptions;

import android.content.SharedPreferences;
import android.text.TextUtils;
import androidx.appcompat.widget.C0070a;
import androidx.compose.foundation.text.input.internal.u;
import androidx.fragment.app.I;
import com.android.billingclient.api.C1473b;
import com.android.billingclient.api.C1474c;
import com.android.billingclient.api.Purchase;
import com.android.billingclient.api.x;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3730t6;
import com.google.android.gms.internal.play_billing.B;
import com.quizlet.billing.manager.BillingLibraryException;
import com.quizlet.db.data.models.persisted.DBUser;
import io.reactivex.rxjava3.core.p;
import io.reactivex.rxjava3.subjects.r;
import java.util.ArrayList;
import java.util.List;
import kotlin.collections.A;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final /* synthetic */ class g implements io.reactivex.rxjava3.functions.h {
    public final /* synthetic */ int a = 0;
    public final /* synthetic */ h b;
    public final /* synthetic */ long c;
    public final /* synthetic */ String d;
    public final /* synthetic */ Object e;
    public final /* synthetic */ Object f;

    public /* synthetic */ g(long j, Purchase purchase, h hVar, String str, String str2) {
        this.b = hVar;
        this.c = j;
        this.d = str;
        this.e = str2;
        this.f = purchase;
    }

    @Override // io.reactivex.rxjava3.functions.h
    public final Object apply(Object obj) {
        String str;
        String str2;
        switch (this.a) {
            case 0:
                b bVar = (b) obj;
                h hVar = this.b;
                hVar.getClass();
                Throwable th = bVar.b;
                if (th != null) {
                    return p.d(th);
                }
                SharedPreferences.Editor editorEdit = hVar.d.a.edit();
                StringBuilder sb = new StringBuilder("register_");
                long j = this.c;
                sb.append(j);
                editorEdit.remove(sb.toString()).apply();
                DBUser dBUser = bVar.a;
                dBUser.getObfuscatedUserId();
                dBUser.getSelfIdentifiedUserType();
                dBUser.getUserUpgradeType();
                dBUser.getIsEligibleForFreeTrial();
                com.quizlet.billing.model.c cVar = hVar.i.i;
                if (cVar == null) {
                    String str3 = this.d;
                    cVar = new com.quizlet.billing.model.c(j, str3, AbstractC3730t6.b(str3), (String) this.e, p.f((Purchase) this.f));
                }
                return p.f(cVar);
            default:
                h hVar2 = this.b;
                if (obj instanceof com.quizlet.billing.model.d) {
                    str = null;
                    ((com.quizlet.billing.model.d) obj).getClass();
                } else {
                    str = ((com.quizlet.data.model.billing.a) obj).a;
                }
                String sku = str;
                com.quizlet.billing.manager.f fVar = hVar2.i;
                fVar.getClass();
                I activity = (I) this.e;
                Intrinsics.checkNotNullParameter(activity, "activity");
                Intrinsics.checkNotNullParameter(sku, "sku");
                j subscriptionPackage = (j) this.f;
                Intrinsics.checkNotNullParameter(subscriptionPackage, "subscriptionPackage");
                String source = this.d;
                Intrinsics.checkNotNullParameter(source, "source");
                C1473b c1473b = fVar.e;
                if (c1473b == null) {
                    Intrinsics.m("billingClient");
                    throw null;
                }
                boolean z = false;
                boolean z2 = !(c1473b.c("subscriptions").a == 0);
                boolean z3 = !true;
                C1473b c1473b2 = fVar.e;
                if (c1473b2 == null) {
                    Intrinsics.m("billingClient");
                    throw null;
                }
                if (z2 || (z3 & (!(c1473b2.c("subscriptionsUpdate").a == 0)))) {
                    io.reactivex.rxjava3.internal.operators.flowable.b bVarD = p.d(new BillingLibraryException(-2, null));
                    Intrinsics.checkNotNullExpressionValue(bVarD, "error(...)");
                    return bVarD;
                }
                r rVar = new r();
                fVar.h = rVar;
                fVar.i = new com.quizlet.billing.model.c(this.c, sku, subscriptionPackage, source, rVar);
                com.quizlet.billing.model.a aVar = fVar.d;
                aVar.getClass();
                Intrinsics.checkNotNullParameter(sku, "sku");
                com.android.billingclient.api.j jVar = (com.android.billingclient.api.j) aVar.b.get(sku);
                if (jVar == null) {
                    io.reactivex.rxjava3.internal.operators.flowable.b bVarD2 = p.d(new BillingLibraryException(-2, "product details not found"));
                    Intrinsics.checkNotNullExpressionValue(bVarD2, "error(...)");
                    return bVarD2;
                }
                Intrinsics.checkNotNullParameter(jVar, "<this>");
                ArrayList arrayList = jVar.i;
                com.android.billingclient.api.i iVar = arrayList != null ? (com.android.billingclient.api.i) CollectionsKt.firstOrNull(arrayList) : null;
                if (iVar == null || (str2 = iVar.a) == null) {
                    io.reactivex.rxjava3.internal.operators.flowable.b bVarD3 = p.d(new BillingLibraryException(-2, "offer token is null"));
                    Intrinsics.checkNotNullExpressionValue(bVarD3, "error(...)");
                    return bVarD3;
                }
                u uVar = new u(7);
                uVar.b = jVar;
                if (jVar.a() != null) {
                    jVar.a().getClass();
                    String str4 = jVar.a().a;
                    if (str4 != null) {
                        uVar.c = str4;
                    }
                }
                if (TextUtils.isEmpty(str2)) {
                    throw new IllegalArgumentException("offerToken can not be empty");
                }
                uVar.c = str2;
                List listB = A.b(new C1474c(uVar));
                C0070a c0070a = new C0070a();
                c0070a.a = 0;
                c0070a.b = true;
                ArrayList arrayList2 = new ArrayList(listB);
                String str5 = fVar.c.e().b;
                if (str5 == null) {
                    str5 = null;
                }
                boolean zIsEmpty = arrayList2.isEmpty();
                if (zIsEmpty) {
                    throw new IllegalArgumentException("Details of the products must be provided.");
                }
                arrayList2.forEach(new x());
                androidx.compose.material.ripple.r rVar2 = new androidx.compose.material.ripple.r();
                if (!zIsEmpty && !((C1474c) arrayList2.get(0)).a.b.optString("packageName").isEmpty()) {
                    z = true;
                }
                rVar2.a = z;
                rVar2.b = str5;
                boolean z4 = true;
                if (TextUtils.isEmpty((String) c0070a.c) && TextUtils.isEmpty(null)) {
                    z4 = false;
                }
                boolean zIsEmpty2 = TextUtils.isEmpty(null);
                if (z4 && !zIsEmpty2) {
                    throw new IllegalArgumentException("Please provide Old SKU purchase information(token/id) or original external transaction id, not both.");
                }
                if (!c0070a.b && !z4 && zIsEmpty2) {
                    throw new IllegalArgumentException("Old SKU purchase information(token/id) or original external transaction id must be provided.");
                }
                com.android.billingclient.api.d dVar = new com.android.billingclient.api.d(0);
                dVar.c = (String) c0070a.c;
                dVar.b = c0070a.a;
                rVar2.c = dVar;
                rVar2.d = new ArrayList();
                rVar2.e = B.n(arrayList2);
                Intrinsics.checkNotNullExpressionValue(rVar2, "with(...)");
                C1473b c1473b3 = fVar.e;
                if (c1473b3 == null) {
                    Intrinsics.m("billingClient");
                    throw null;
                }
                com.android.billingclient.api.e eVarE = c1473b3.e(activity, rVar2);
                Intrinsics.checkNotNullExpressionValue(eVarE, "launchBillingFlow(...)");
                if (eVarE.a != 0) {
                    return p.d(new BillingLibraryException(eVarE.a, null));
                }
                fVar.j = true;
                r rVar3 = fVar.h;
                Intrinsics.d(rVar3);
                return rVar3;
        }
    }

    public /* synthetic */ g(h hVar, I i, long j, j jVar, String str) {
        this.b = hVar;
        this.e = i;
        this.c = j;
        this.f = jVar;
        this.d = str;
    }
}
