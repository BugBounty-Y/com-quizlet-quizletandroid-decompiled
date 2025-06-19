package androidx.work.impl.model;

import android.R;
import android.content.ComponentName;
import android.os.Bundle;
import android.os.RemoteException;
import android.util.JsonReader;
import androidx.core.view.V;
import androidx.viewpager2.widget.ViewPager2;
import androidx.work.impl.WorkDatabase_Impl;
import com.google.android.gms.ads.nonagon.signalgeneration.AbstractC1642h;
import com.google.android.gms.internal.ads.AbstractC1795We;
import com.google.android.gms.internal.ads.AbstractC1972di;
import com.google.android.gms.internal.ads.AbstractC1981ds;
import com.google.android.gms.internal.ads.AbstractC2096gb;
import com.google.android.gms.internal.ads.AbstractC2543qs;
import com.google.android.gms.internal.ads.AbstractC2773w7;
import com.google.android.gms.internal.ads.BC;
import com.google.android.gms.internal.ads.C1703Hc;
import com.google.android.gms.internal.ads.C1721Kc;
import com.google.android.gms.internal.ads.C1735Me;
import com.google.android.gms.internal.ads.C1741Ne;
import com.google.android.gms.internal.ads.C1747Oe;
import com.google.android.gms.internal.ads.C1765Re;
import com.google.android.gms.internal.ads.C1969df;
import com.google.android.gms.internal.ads.C2239jp;
import com.google.android.gms.internal.ads.Do;
import com.google.android.gms.internal.ads.EC;
import com.google.android.gms.internal.ads.IC;
import com.google.android.gms.internal.ads.Ig;
import com.google.android.gms.internal.ads.Jq;
import com.google.android.gms.internal.ads.LA;
import com.google.android.gms.internal.ads.Lo;
import com.google.android.gms.internal.ads.Ok;
import com.google.android.gms.internal.ads.Vp;
import com.google.android.gms.internal.ads.Wg;
import com.google.android.gms.internal.ads.Xp;
import com.google.android.gms.internal.ads.Zp;
import com.google.android.gms.internal.ads.zzfby;
import com.google.android.gms.internal.measurement.C2992g;
import com.google.android.gms.internal.measurement.C3005i2;
import com.google.android.gms.internal.measurement.C3022m;
import com.google.android.gms.internal.measurement.C3032o;
import com.google.android.gms.internal.measurement.C3039p1;
import com.google.android.gms.internal.measurement.C3056t;
import com.google.android.gms.internal.measurement.InterfaceC3027n;
import com.google.android.gms.internal.measurement.Z;
import com.google.android.gms.internal.measurement.j4;
import com.google.android.gms.internal.mlkit_vision_barcode.Q;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3554w3;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3560x3;
import com.google.android.gms.internal.mlkit_vision_common.V2;
import com.quizlet.data.model.L;
import com.quizlet.db.data.caches.UserInfoCache;
import com.quizlet.db.data.models.persisted.DBStudySet;
import com.quizlet.remote.model.base.ApiThreeWrapper;
import java.io.IOException;
import java.io.Reader;
import java.io.StringReader;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.AbstractC5040y;
import org.json.JSONException;
import org.json.JSONObject;
import retrofit2.K;

/* loaded from: classes.dex */
public final class n {
    public final Object a;
    public final Object b;
    public Object c;
    public final Object d;

    public n(C1765Re c1765Re, com.android.billingclient.api.s sVar) {
        int i = 7;
        int i2 = 2;
        this.b = c1765Re;
        this.a = sVar;
        this.c = BC.b(new Ok(c1765Re.p, 28));
        C2239jp c2239jp = new C2239jp(sVar, 1);
        C2239jp c2239jp2 = new C2239jp(sVar, i2);
        C2239jp c2239jp3 = new C2239jp(sVar, 4);
        C1741Ne c1741Ne = c1765Re.g;
        BC bc = c1765Re.d;
        new com.google.android.gms.ads.nonagon.signalgeneration.t(c1741Ne, bc, c2239jp, c2239jp2, c2239jp3, 17);
        new C1735Me(c1741Ne, 27);
        C2239jp c2239jp4 = new C2239jp(sVar, 0);
        new C1969df(c2239jp4, 23);
        new C1747Oe(bc, c1741Ne, i);
        C2239jp c2239jp5 = new C2239jp(sVar, 3);
        C2239jp c2239jp6 = new C2239jp(sVar, 6);
        C2239jp c2239jp7 = new C2239jp(sVar, i);
        BC bc2 = c1765Re.O;
        new Ig(bc2, c2239jp5, c2239jp3, c2239jp4, bc, c2239jp6, c2239jp7);
        new Lo(c2239jp4, bc2, bc, i2);
        C2239jp c2239jp8 = new C2239jp(sVar, 5);
        BC bcB = BC.b(AbstractC1972di.E);
        BC bcB2 = BC.b(AbstractC1795We.q);
        BC bcB3 = BC.b(LA.q);
        BC bcB4 = BC.b(AbstractC2096gb.q);
        int i3 = EC.b;
        LinkedHashMap linkedHashMapO = AbstractC2543qs.o(4);
        Jq jq = Jq.GMS_SIGNALS;
        AbstractC1981ds.g(bcB, "provider");
        linkedHashMapO.put(jq, bcB);
        Jq jq2 = Jq.BUILD_URL;
        AbstractC1981ds.g(bcB2, "provider");
        linkedHashMapO.put(jq2, bcB2);
        Jq jq3 = Jq.HTTP;
        AbstractC1981ds.g(bcB3, "provider");
        linkedHashMapO.put(jq3, bcB3);
        Jq jq4 = Jq.PRE_PROCESS;
        AbstractC1981ds.g(bcB4, "provider");
        linkedHashMapO.put(jq4, bcB4);
        BC bcB5 = BC.b(new C1703Hc(c2239jp8, c1765Re.g, new EC(linkedHashMapO), 12));
        int i4 = IC.c;
        List list = Collections.EMPTY_LIST;
        ArrayList arrayList = new ArrayList(1);
        arrayList.add(bcB5);
        this.d = BC.b(new Do(c1765Re.d, new Wg(new IC(list, arrayList), 25)));
    }

    public static final L a(n nVar, K k) {
        List listB;
        ApiThreeWrapper apiThreeWrapper = (ApiThreeWrapper) k.b;
        if (apiThreeWrapper == null || (listB = ((com.quizlet.remote.model.course.c) nVar.b).b(apiThreeWrapper)) == null) {
            listB = kotlin.collections.K.a;
        }
        okhttp3.r rVar = k.a.f;
        Intrinsics.checkNotNullExpressionValue(rVar, "headers(...)");
        return new L(Q.a(rVar), listB);
    }

    public static n j(Reader reader, Bundle bundle) {
        try {
            try {
                return new n(new JsonReader(reader), bundle);
            } finally {
                com.google.android.gms.common.util.c.d(reader);
            }
        } catch (IOException | AssertionError | IllegalStateException | NumberFormatException | JSONException e) {
            throw new zzfby("unable to parse ServerResponse", e);
        }
    }

    public Enum b(long j, boolean z, long j2, kotlin.coroutines.jvm.internal.c cVar) {
        UserInfoCache userInfoCache = (UserInfoCache) this.c;
        return j2 == userInfoCache.getPersonId() ? com.quizlet.features.setpage.usecases.g.a : userInfoCache.b() ? z ? e(j, cVar) : d(j, com.quizlet.data.interactor.set.permissions.a.b, cVar) : com.quizlet.features.setpage.usecases.g.c;
    }

    public Enum c(DBStudySet dBStudySet, kotlin.coroutines.jvm.internal.i iVar) {
        if (dBStudySet.getAccessType() != 2) {
            long creatorId = dBStudySet.getCreatorId();
            UserInfoCache userInfoCache = (UserInfoCache) this.c;
            if (creatorId != userInfoCache.getPersonId()) {
                return userInfoCache.b() ? dBStudySet.getPasswordUse() ? e(dBStudySet.getId(), iVar) : d(dBStudySet.getId(), com.quizlet.data.interactor.set.permissions.a.a, iVar) : com.quizlet.features.setpage.usecases.g.c;
            }
        }
        return com.quizlet.features.setpage.usecases.g.a;
    }

    /* JADX WARN: Removed duplicated region for block: B:8:0x0014  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Enum d(long r9, com.quizlet.data.interactor.set.permissions.a r11, kotlin.coroutines.jvm.internal.c r12) {
        /*
            r8 = this;
            boolean r0 = r12 instanceof com.quizlet.features.setpage.usecases.j
            if (r0 == 0) goto L14
            r0 = r12
            com.quizlet.features.setpage.usecases.j r0 = (com.quizlet.features.setpage.usecases.j) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L14
            int r1 = r1 - r2
            r0.l = r1
        L12:
            r7 = r0
            goto L1a
        L14:
            com.quizlet.features.setpage.usecases.j r0 = new com.quizlet.features.setpage.usecases.j
            r0.<init>(r8, r12)
            goto L12
        L1a:
            java.lang.Object r12 = r7.j
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r7.l
            r2 = 1
            if (r1 == 0) goto L31
            if (r1 != r2) goto L29
            androidx.glance.appwidget.protobuf.Z.e(r12)
            goto L4c
        L29:
            java.lang.IllegalStateException r9 = new java.lang.IllegalStateException
            java.lang.String r10 = "call to 'resume' before 'invoke' with coroutine"
            r9.<init>(r10)
            throw r9
        L31:
            androidx.glance.appwidget.protobuf.Z.e(r12)
            java.lang.Object r12 = r8.c
            com.quizlet.db.data.caches.UserInfoCache r12 = (com.quizlet.db.data.caches.UserInfoCache) r12
            long r4 = r12.getPersonId()
            r7.l = r2
            java.lang.Object r12 = r8.b
            r1 = r12
            com.quizlet.data.repository.user.a r1 = (com.quizlet.data.repository.user.a) r1
            r2 = r9
            r6 = r11
            java.lang.Object r12 = r1.f(r2, r4, r6, r7)
            if (r12 != r0) goto L4c
            return r0
        L4c:
            java.lang.Boolean r12 = (java.lang.Boolean) r12
            boolean r9 = r12.booleanValue()
            if (r9 == 0) goto L57
            com.quizlet.features.setpage.usecases.g r9 = com.quizlet.features.setpage.usecases.g.a
            return r9
        L57:
            com.quizlet.features.setpage.usecases.g r9 = com.quizlet.features.setpage.usecases.g.c
            return r9
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.work.impl.model.n.d(long, com.quizlet.data.interactor.set.permissions.a, kotlin.coroutines.jvm.internal.c):java.lang.Enum");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Enum e(long r5, kotlin.coroutines.jvm.internal.c r7) {
        /*
            r4 = this;
            boolean r0 = r7 instanceof com.quizlet.features.setpage.usecases.k
            if (r0 == 0) goto L13
            r0 = r7
            com.quizlet.features.setpage.usecases.k r0 = (com.quizlet.features.setpage.usecases.k) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            com.quizlet.features.setpage.usecases.k r0 = new com.quizlet.features.setpage.usecases.k
            r0.<init>(r4, r7)
        L18:
            java.lang.Object r7 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 1
            if (r2 == 0) goto L2f
            if (r2 != r3) goto L27
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L75
        L27:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L2f:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            r0.l = r3
            com.quizlet.infra.legacysyncengine.orm.b r7 = new com.quizlet.infra.legacysyncengine.orm.b
            com.quizlet.db.data.models.persisted.base.ModelType<com.quizlet.db.data.models.persisted.DBEnteredSetPassword> r2 = com.quizlet.db.data.models.persisted.base.Models.ENTERED_SET_PASSWORD
            r7.<init>(r2)
            com.quizlet.db.data.orm.Relationship<com.quizlet.db.data.models.persisted.DBEnteredSetPassword, com.quizlet.db.data.models.persisted.DBStudySet> r2 = com.quizlet.db.data.models.persisted.fields.DBEnteredSetPasswordFields.SET
            java.lang.Long r3 = new java.lang.Long
            r3.<init>(r5)
            r7.b(r3, r2)
            com.quizlet.infra.legacysyncengine.orm.query.a r5 = r7.a()
            java.lang.Object r6 = r4.d
            com.quizlet.infra.legacysyncengine.net.c r6 = (com.quizlet.infra.legacysyncengine.net.c) r6
            r6.getClass()
            androidx.camera.camera2.internal.T r7 = new androidx.camera.camera2.internal.T
            java.util.Set r2 = com.quizlet.infra.legacysyncengine.net.c.e
            r3 = 21
            r7.<init>(r6, r5, r2, r3)
            com.jakewharton.rxbinding4.a r5 = new com.jakewharton.rxbinding4.a
            r6 = 3
            r5.<init>(r7, r6)
            java.lang.String r6 = "fetchAll(...)"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r5, r6)
            kotlinx.coroutines.flow.c r5 = com.google.android.gms.internal.mlkit_vision_camera.K1.f(r5)
            androidx.datastore.core.t r6 = new androidx.datastore.core.t
            r7 = 3
            r6.<init>(r5, r7)
            java.lang.Object r7 = kotlinx.coroutines.flow.e0.u(r6, r0)
            if (r7 != r1) goto L75
            return r1
        L75:
            java.lang.Boolean r7 = (java.lang.Boolean) r7
            boolean r5 = r7.booleanValue()
            if (r5 == 0) goto L80
            com.quizlet.features.setpage.usecases.g r5 = com.quizlet.features.setpage.usecases.g.a
            return r5
        L80:
            com.quizlet.features.setpage.usecases.g r5 = com.quizlet.features.setpage.usecases.g.b
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.work.impl.model.n.e(long, kotlin.coroutines.jvm.internal.c):java.lang.Enum");
    }

    /* JADX WARN: Removed duplicated region for block: B:8:0x0014  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object f(long r10, boolean r12, long r13, kotlin.coroutines.jvm.internal.c r15) {
        /*
            r9 = this;
            boolean r0 = r15 instanceof com.quizlet.features.setpage.usecases.m
            if (r0 == 0) goto L14
            r0 = r15
            com.quizlet.features.setpage.usecases.m r0 = (com.quizlet.features.setpage.usecases.m) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L14
            int r1 = r1 - r2
            r0.l = r1
        L12:
            r7 = r0
            goto L1a
        L14:
            com.quizlet.features.setpage.usecases.m r0 = new com.quizlet.features.setpage.usecases.m
            r0.<init>(r9, r15)
            goto L12
        L1a:
            java.lang.Object r15 = r7.j
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r7.l
            r8 = 1
            if (r1 == 0) goto L31
            if (r1 != r8) goto L29
            androidx.glance.appwidget.protobuf.Z.e(r15)
            goto L41
        L29:
            java.lang.IllegalStateException r10 = new java.lang.IllegalStateException
            java.lang.String r11 = "call to 'resume' before 'invoke' with coroutine"
            r10.<init>(r11)
            throw r10
        L31:
            androidx.glance.appwidget.protobuf.Z.e(r15)
            r7.l = r8
            r1 = r9
            r2 = r10
            r4 = r12
            r5 = r13
            java.lang.Enum r15 = r1.b(r2, r4, r5, r7)
            if (r15 != r0) goto L41
            return r0
        L41:
            com.quizlet.features.setpage.usecases.g r15 = (com.quizlet.features.setpage.usecases.g) r15
            com.quizlet.features.setpage.usecases.g r10 = com.quizlet.features.setpage.usecases.g.a
            if (r15 == r10) goto L4d
            com.quizlet.features.setpage.usecases.g r10 = com.quizlet.features.setpage.usecases.g.b
            if (r15 != r10) goto L4c
            goto L4d
        L4c:
            r8 = 0
        L4d:
            java.lang.Boolean r10 = java.lang.Boolean.valueOf(r8)
            return r10
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.work.impl.model.n.f(long, boolean, long, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public boolean g(DBStudySet set) {
        Intrinsics.checkNotNullParameter(set, "set");
        return set.getId() > 0 && set.getAccessType() == 0 && set.getCreatorId() != ((UserInfoCache) this.c).getPersonId() && !set.getPasswordUse();
    }

    public void h(String str) {
        Bundle bundle = new Bundle();
        synchronized (this.a) {
            try {
                try {
                    ((android.support.customtabs.b) ((android.support.customtabs.d) this.b)).f0((androidx.browser.customtabs.g) this.c, str, bundle);
                } catch (RemoteException unused) {
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public void i() {
        int itemCount;
        int i = R.id.accessibilityActionPageLeft;
        ViewPager2 viewPager2 = (ViewPager2) this.d;
        V.l(R.id.accessibilityActionPageLeft, viewPager2);
        V.i(0, viewPager2);
        V.l(R.id.accessibilityActionPageRight, viewPager2);
        V.i(0, viewPager2);
        V.l(R.id.accessibilityActionPageUp, viewPager2);
        V.i(0, viewPager2);
        V.l(R.id.accessibilityActionPageDown, viewPager2);
        V.i(0, viewPager2);
        if (viewPager2.getAdapter() == null || (itemCount = viewPager2.getAdapter().getItemCount()) == 0 || !viewPager2.r) {
            return;
        }
        int orientation = viewPager2.getOrientation();
        com.google.android.gms.internal.instantapps.a aVar = (com.google.android.gms.internal.instantapps.a) this.b;
        com.google.android.gms.auth.api.signin.internal.h hVar = (com.google.android.gms.auth.api.signin.internal.h) this.a;
        if (orientation != 0) {
            if (viewPager2.d < itemCount - 1) {
                V.m(viewPager2, new androidx.core.view.accessibility.d(R.id.accessibilityActionPageDown, (CharSequence) null), hVar);
            }
            if (viewPager2.d > 0) {
                V.m(viewPager2, new androidx.core.view.accessibility.d(R.id.accessibilityActionPageUp, (CharSequence) null), aVar);
                return;
            }
            return;
        }
        boolean z = viewPager2.g.b.getLayoutDirection() == 1;
        int i2 = z ? 16908360 : 16908361;
        if (z) {
            i = 16908361;
        }
        if (viewPager2.d < itemCount - 1) {
            V.m(viewPager2, new androidx.core.view.accessibility.d(i2, (CharSequence) null), hVar);
        }
        if (viewPager2.d > 0) {
            V.m(viewPager2, new androidx.core.view.accessibility.d(i, (CharSequence) null), aVar);
        }
    }

    public InterfaceC3027n k(C1721Kc c1721Kc, C3039p1... c3039p1Arr) {
        InterfaceC3027n interfaceC3027nA = InterfaceC3027n.Q0;
        for (C3039p1 c3039p1 : c3039p1Arr) {
            interfaceC3027nA = AbstractC3560x3.a(c3039p1);
            AbstractC3554w3.c((C1721Kc) this.c);
            if ((interfaceC3027nA instanceof C3032o) || (interfaceC3027nA instanceof C3022m)) {
                interfaceC3027nA = ((C3056t) this.a).a(c1721Kc, interfaceC3027nA);
            }
        }
        return interfaceC3027nA;
    }

    public n() {
        C3056t c3056t = new C3056t(0);
        this.a = c3056t;
        C1721Kc c1721Kc = new C1721Kc(null, c3056t);
        this.c = c1721Kc;
        this.b = c1721Kc.g();
        C3005i2 c3005i2 = new C3005i2(1);
        this.d = c3005i2;
        c1721Kc.n("require", new j4(c3005i2));
        ((HashMap) c3005i2.a).put("internal.platform", new Z());
        c1721Kc.n("runtime.counter", new C2992g(Double.valueOf(0.0d)));
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r0v10 */
    /* JADX WARN: Type inference failed for: r0v4, types: [java.util.List] */
    /* JADX WARN: Type inference failed for: r0v5, types: [java.lang.Object] */
    /* JADX WARN: Type inference failed for: r0v7 */
    /* JADX WARN: Type inference failed for: r0v8, types: [java.util.ArrayList] */
    /* JADX WARN: Type inference failed for: r0v9 */
    public n(JsonReader jsonReader, Bundle bundle) throws IOException {
        this.d = bundle;
        if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.h2)).booleanValue() && bundle != null) {
            AbstractC1642h.t(com.google.android.gms.ads.internal.j.C.k, bundle, "server-response-parse-start");
        }
        ?? arrayList = Collections.EMPTY_LIST;
        ArrayList arrayList2 = new ArrayList();
        jsonReader.beginObject();
        Xp xp = null;
        while (jsonReader.hasNext()) {
            String strNextName = jsonReader.nextName();
            if ("responses".equals(strNextName)) {
                jsonReader.beginArray();
                jsonReader.beginObject();
                while (jsonReader.hasNext()) {
                    String strNextName2 = jsonReader.nextName();
                    if ("ad_configs".equals(strNextName2)) {
                        arrayList = new ArrayList();
                        jsonReader.beginArray();
                        while (jsonReader.hasNext()) {
                            arrayList.add(new Vp(jsonReader));
                        }
                        jsonReader.endArray();
                    } else if (strNextName2.equals("common")) {
                        xp = new Xp(jsonReader);
                        if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.i2)).booleanValue() && bundle != null) {
                            bundle.putLong("normalize-ad-response-start", xp.s);
                            bundle.putLong("normalize-ad-response-end", xp.t);
                        }
                    } else {
                        jsonReader.skipValue();
                    }
                }
                jsonReader.endObject();
                jsonReader.endArray();
            } else if (strNextName.equals("actions")) {
                jsonReader.beginArray();
                while (jsonReader.hasNext()) {
                    jsonReader.beginObject();
                    String strNextString = null;
                    JSONObject jSONObjectG = null;
                    while (jsonReader.hasNext()) {
                        String strNextName3 = jsonReader.nextName();
                        if ("name".equals(strNextName3)) {
                            strNextString = jsonReader.nextString();
                        } else if ("info".equals(strNextName3)) {
                            jSONObjectG = V2.g(jsonReader);
                        } else {
                            jsonReader.skipValue();
                        }
                    }
                    if (strNextString != null) {
                        arrayList2.add(new Zp(strNextString, jSONObjectG));
                    }
                    jsonReader.endObject();
                }
                jsonReader.endArray();
            }
        }
        this.c = arrayList2;
        this.a = arrayList;
        this.b = xp == null ? new Xp(new JsonReader(new StringReader("{}"))) : xp;
    }

    public n(com.perimeterx.mobile_sdk.detections.device.b fingerprint, com.perimeterx.mobile_sdk.detections.a aVar, com.perimeterx.mobile_sdk.models.b bVar, Integer num) {
        Intrinsics.checkNotNullParameter(fingerprint, "fingerprint");
        this.a = fingerprint;
        this.b = aVar;
        this.c = bVar;
        this.d = num;
    }

    public n(AbstractC5040y dispatcher, com.quizlet.data.repository.user.a getStudySetPermissionUseCase, UserInfoCache userInfoCache, com.quizlet.infra.legacysyncengine.net.c loader) {
        Intrinsics.checkNotNullParameter(dispatcher, "dispatcher");
        Intrinsics.checkNotNullParameter(getStudySetPermissionUseCase, "getStudySetPermissionUseCase");
        Intrinsics.checkNotNullParameter(userInfoCache, "userInfoCache");
        Intrinsics.checkNotNullParameter(loader, "loader");
        this.a = dispatcher;
        this.b = getStudySetPermissionUseCase;
        this.c = userInfoCache;
        this.d = loader;
    }

    public n(com.quizlet.remote.service.i service, com.quizlet.remote.model.course.c courseMapper, com.quizlet.quizletandroid.ui.folder.logging.a folderMapper, AbstractC5040y ioDispatcher) {
        Intrinsics.checkNotNullParameter(service, "service");
        Intrinsics.checkNotNullParameter(courseMapper, "courseMapper");
        Intrinsics.checkNotNullParameter(folderMapper, "folderMapper");
        Intrinsics.checkNotNullParameter(ioDispatcher, "ioDispatcher");
        this.a = service;
        this.b = courseMapper;
        this.c = folderMapper;
        this.d = ioDispatcher;
    }

    public n(WorkDatabase_Impl database) {
        this.a = database;
        Intrinsics.checkNotNullParameter(database, "database");
        this.b = new b(database, 4);
        this.c = new h(database, 2);
        this.d = new h(database, 3);
    }

    public n(android.support.customtabs.d dVar, androidx.browser.customtabs.g gVar, ComponentName componentName) {
        this.a = new Object();
        this.b = dVar;
        this.c = gVar;
        this.d = componentName;
    }

    public n(ViewPager2 viewPager2) {
        this.d = viewPager2;
        int i = 16;
        this.a = new com.google.android.gms.auth.api.signin.internal.h(this, i);
        this.b = new com.google.android.gms.internal.instantapps.a(this, i);
    }
}
