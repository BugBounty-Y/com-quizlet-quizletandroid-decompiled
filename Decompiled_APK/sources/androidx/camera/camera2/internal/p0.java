package androidx.camera.camera2.internal;

import android.content.Context;
import android.content.IntentFilter;
import android.os.Build;
import android.text.TextUtils;
import androidx.camera.core.impl.EnumC0184x;
import androidx.camera.core.impl.InterfaceC0159a0;
import androidx.camera.core.impl.InterfaceC0183w;
import androidx.compose.runtime.F0;
import com.google.android.gms.common.ConnectionResult;
import com.google.android.gms.common.api.internal.C1643a;
import com.google.android.gms.common.api.internal.C1647e;
import com.google.android.gms.common.internal.InterfaceC1654d;
import com.google.android.gms.internal.ads.AbstractC2270kd;
import com.google.android.gms.internal.ads.AbstractC2415nt;
import com.google.android.gms.internal.ads.AbstractC2773w7;
import com.google.android.gms.internal.ads.C1896bt;
import com.google.android.gms.internal.ads.C1982dt;
import com.google.android.gms.internal.ads.C2158ht;
import com.google.android.gms.internal.ads.InterfaceC2529qe;
import com.google.android.gms.internal.ads.RunnableC2286kt;
import com.google.android.gms.internal.ads.Sq;
import com.google.android.gms.internal.ads.Tm;
import com.google.android.gms.internal.measurement.AbstractC3053s1;
import com.google.android.gms.internal.mlkit_vision_barcode.Y5;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import kotlin.NoWhenBranchMatchedException;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.internal.AbstractC5047c0;

/* loaded from: classes.dex */
public final class p0 implements InterfaceC0159a0, InterfaceC1654d, kotlinx.serialization.modules.e {
    public Object a;
    public boolean b;
    public Object c;
    public Object d;
    public Object e;
    public Object f;

    public p0(Context context, com.android.billingclient.api.k kVar, androidx.work.impl.model.c cVar) {
        this.c = context;
        this.d = kVar;
        this.a = cVar;
        this.e = new com.android.billingclient.api.C(this, true);
        this.f = new com.android.billingclient.api.C(this, false);
    }

    public static void l(p0 p0Var, kotlin.reflect.c baseClass, kotlin.reflect.c concreteClass, KSerializer concreteSerializer) {
        Object next;
        kotlin.reflect.c cVar;
        p0Var.getClass();
        Intrinsics.checkNotNullParameter(baseClass, "baseClass");
        Intrinsics.checkNotNullParameter(concreteClass, "concreteClass");
        Intrinsics.checkNotNullParameter(concreteSerializer, "concreteSerializer");
        String strA = concreteSerializer.getDescriptor().a();
        HashMap map = (HashMap) p0Var.d;
        Object map2 = map.get(baseClass);
        if (map2 == null) {
            map2 = new HashMap();
            map.put(baseClass, map2);
        }
        Map map3 = (Map) map2;
        HashMap map4 = (HashMap) p0Var.e;
        Object map5 = map4.get(baseClass);
        if (map5 == null) {
            map5 = new HashMap();
            map4.put(baseClass, map5);
        }
        Map map6 = (Map) map5;
        KSerializer kSerializer = (KSerializer) map3.get(concreteClass);
        if (kSerializer != null && !kSerializer.equals(concreteSerializer)) {
            Intrinsics.checkNotNullParameter(baseClass, "baseClass");
            Intrinsics.checkNotNullParameter(concreteClass, "concreteClass");
            throw new kotlinx.serialization.modules.d("Serializer for " + concreteClass + " already registered in the scope of " + baseClass);
        }
        KSerializer kSerializer2 = (KSerializer) map6.get(strA);
        if (kSerializer2 == null || kSerializer2.equals(concreteSerializer)) {
            map3.put(concreteClass, concreteSerializer);
            map6.put(strA, concreteSerializer);
            return;
        }
        Intrinsics.checkNotNullParameter(map3, "<this>");
        Iterator it2 = ((Iterable) CollectionsKt.D(map3.entrySet()).b).iterator();
        while (true) {
            if (!it2.hasNext()) {
                next = null;
                break;
            } else {
                next = it2.next();
                if (((Map.Entry) next).getValue() == kSerializer2) {
                    break;
                }
            }
        }
        Map.Entry entry = (Map.Entry) next;
        if (entry == null || (cVar = (kotlin.reflect.c) entry.getKey()) == null) {
            throw new IllegalStateException(("Name " + strA + " is registered in the module but no Kotlin class is associated with it.").toString());
        }
        throw new IllegalArgumentException("Multiple polymorphic serializers in a scope of '" + baseClass + "' have the same serial name '" + strA + "': " + concreteSerializer + " for '" + concreteClass + "' and " + kSerializer2 + " for '" + cVar + '\'');
    }

    public static void m(p0 p0Var, kotlin.reflect.c forClass, kotlinx.serialization.modules.c provider) {
        p0Var.getClass();
        Intrinsics.checkNotNullParameter(forClass, "forClass");
        Intrinsics.checkNotNullParameter(provider, "provider");
        HashMap map = (HashMap) p0Var.c;
        kotlinx.serialization.modules.c cVar = (kotlinx.serialization.modules.c) map.get(forClass);
        if (cVar != null && !cVar.equals(provider)) {
            throw new kotlinx.serialization.modules.d("Contextual serializer or serializer provider for " + forClass + " already registered in this module");
        }
        map.put(forClass, provider);
        if (AbstractC5047c0.h(forClass)) {
            p0Var.b = true;
        }
    }

    @Override // kotlinx.serialization.modules.e
    public void a(kotlin.reflect.c kClass) {
        kotlinx.serialization.internal.q0 serializer = kotlinx.serialization.internal.q0.a;
        Intrinsics.checkNotNullParameter(kClass, "kClass");
        Intrinsics.checkNotNullParameter(serializer, "serializer");
        Intrinsics.checkNotNullParameter(serializer, "serializer");
        m(this, kClass, new kotlinx.serialization.modules.a());
    }

    @Override // com.google.android.gms.common.internal.InterfaceC1654d
    public void b(ConnectionResult connectionResult) {
        ((C1647e) this.f).n.post(new com.google.common.util.concurrent.d(this, false, connectionResult, 21));
    }

    @Override // kotlinx.serialization.modules.e
    public void c(kotlin.reflect.c kClass, com.sdk.growthbook.utils.a provider) {
        Intrinsics.checkNotNullParameter(kClass, "kClass");
        Intrinsics.checkNotNullParameter(provider, "provider");
        m(this, kClass, new kotlinx.serialization.modules.b(provider));
    }

    @Override // kotlinx.serialization.modules.e
    public void d(kotlin.reflect.c baseClass, Function1 defaultSerializerProvider) {
        Intrinsics.checkNotNullParameter(baseClass, "baseClass");
        Intrinsics.checkNotNullParameter(defaultSerializerProvider, "defaultSerializerProvider");
        Intrinsics.checkNotNullParameter(baseClass, "baseClass");
        Intrinsics.checkNotNullParameter(defaultSerializerProvider, "defaultSerializerProvider");
        HashMap map = (HashMap) this.a;
        Function1 function1 = (Function1) map.get(baseClass);
        if (function1 == null || function1.equals(defaultSerializerProvider)) {
            map.put(baseClass, defaultSerializerProvider);
            return;
        }
        throw new IllegalArgumentException("Default serializers provider for " + baseClass + " is already registered: " + function1);
    }

    @Override // kotlinx.serialization.modules.e
    public void e(kotlin.reflect.c baseClass, kotlin.reflect.c actualClass, KSerializer actualSerializer) {
        Intrinsics.checkNotNullParameter(baseClass, "baseClass");
        Intrinsics.checkNotNullParameter(actualClass, "actualClass");
        Intrinsics.checkNotNullParameter(actualSerializer, "actualSerializer");
        l(this, baseClass, actualClass, actualSerializer);
    }

    @Override // kotlinx.serialization.modules.e
    public void f(kotlin.reflect.c baseClass, Function1 defaultDeserializerProvider) {
        Intrinsics.checkNotNullParameter(baseClass, "baseClass");
        Intrinsics.checkNotNullParameter(defaultDeserializerProvider, "defaultDeserializerProvider");
        Intrinsics.checkNotNullParameter(baseClass, "baseClass");
        Intrinsics.checkNotNullParameter(defaultDeserializerProvider, "defaultDeserializerProvider");
        HashMap map = (HashMap) this.f;
        Function1 function1 = (Function1) map.get(baseClass);
        if (function1 == null || function1.equals(defaultDeserializerProvider)) {
            map.put(baseClass, defaultDeserializerProvider);
            return;
        }
        throw new IllegalArgumentException("Default deserializers provider for " + baseClass + " is already registered: " + function1);
    }

    public p0 g() {
        return new p0((HashMap) this.c, (HashMap) this.d, (HashMap) this.a, (HashMap) this.e, (HashMap) this.f, this.b);
    }

    /* JADX WARN: Type inference failed for: r0v1, types: [java.lang.Object, java.util.Map] */
    /* JADX WARN: Type inference failed for: r0v10, types: [java.lang.Object, java.util.Map] */
    /* JADX WARN: Type inference failed for: r0v4, types: [java.lang.Object, java.util.Map] */
    /* JADX WARN: Type inference failed for: r0v7, types: [java.lang.Object, java.util.Map] */
    public void h(kotlinx.serialization.modules.e collector) {
        Intrinsics.checkNotNullParameter(collector, "collector");
        for (Map.Entry entry : this.c.entrySet()) {
            kotlin.reflect.c cVar = (kotlin.reflect.c) entry.getKey();
            kotlinx.serialization.modules.c cVar2 = (kotlinx.serialization.modules.c) entry.getValue();
            if (cVar2 instanceof kotlinx.serialization.modules.a) {
                Intrinsics.e(cVar, "null cannot be cast to non-null type kotlin.reflect.KClass<kotlin.Any>");
                ((kotlinx.serialization.modules.a) cVar2).getClass();
                kotlinx.serialization.internal.q0 q0Var = kotlinx.serialization.internal.q0.a;
                collector.a(cVar);
            } else {
                if (!(cVar2 instanceof kotlinx.serialization.modules.b)) {
                    throw new NoWhenBranchMatchedException();
                }
                collector.c(cVar, ((kotlinx.serialization.modules.b) cVar2).a);
            }
        }
        for (Map.Entry entry2 : this.d.entrySet()) {
            kotlin.reflect.c cVar3 = (kotlin.reflect.c) entry2.getKey();
            for (Map.Entry entry3 : ((Map) entry2.getValue()).entrySet()) {
                kotlin.reflect.c cVar4 = (kotlin.reflect.c) entry3.getKey();
                KSerializer kSerializer = (KSerializer) entry3.getValue();
                Intrinsics.e(cVar3, "null cannot be cast to non-null type kotlin.reflect.KClass<kotlin.Any>");
                Intrinsics.e(cVar4, "null cannot be cast to non-null type kotlin.reflect.KClass<kotlin.Any>");
                Intrinsics.e(kSerializer, "null cannot be cast to non-null type kotlinx.serialization.KSerializer<T of kotlinx.serialization.internal.Platform_commonKt.cast>");
                collector.e(cVar3, cVar4, kSerializer);
            }
        }
        for (Map.Entry entry4 : this.a.entrySet()) {
            kotlin.reflect.c cVar5 = (kotlin.reflect.c) entry4.getKey();
            Function1 function1 = (Function1) entry4.getValue();
            Intrinsics.e(cVar5, "null cannot be cast to non-null type kotlin.reflect.KClass<kotlin.Any>");
            Intrinsics.e(function1, "null cannot be cast to non-null type kotlin.Function1<@[ParameterName(name = \"value\")] kotlin.Any, kotlinx.serialization.SerializationStrategy<kotlin.Any>?>");
            kotlin.jvm.internal.O.d(1, function1);
            collector.d(cVar5, function1);
        }
        for (Map.Entry entry5 : this.f.entrySet()) {
            kotlin.reflect.c cVar6 = (kotlin.reflect.c) entry5.getKey();
            Function1 function12 = (Function1) entry5.getValue();
            Intrinsics.e(cVar6, "null cannot be cast to non-null type kotlin.reflect.KClass<kotlin.Any>");
            Intrinsics.e(function12, "null cannot be cast to non-null type kotlin.Function1<@[ParameterName(name = \"className\")] kotlin.String?, kotlinx.serialization.DeserializationStrategy<kotlin.Any>?>");
            kotlin.jvm.internal.O.d(1, function12);
            collector.f(cVar6, function12);
        }
    }

    /* JADX WARN: Type inference failed for: r0v2, types: [java.lang.Object, java.util.Map] */
    public KSerializer i(kotlin.reflect.c kClass, List typeArgumentsSerializers) {
        Intrinsics.checkNotNullParameter(kClass, "kClass");
        Intrinsics.checkNotNullParameter(typeArgumentsSerializers, "typeArgumentsSerializers");
        kotlinx.serialization.modules.c cVar = (kotlinx.serialization.modules.c) this.c.get(kClass);
        KSerializer kSerializerA = cVar != null ? cVar.a(typeArgumentsSerializers) : null;
        if (kSerializerA != null) {
            return kSerializerA;
        }
        return null;
    }

    public float j() {
        return ((F0) this.a).i();
    }

    @Override // androidx.camera.core.impl.InterfaceC0159a0
    public void k(Object obj) {
        EnumC0184x enumC0184x = (EnumC0184x) obj;
        EnumC0184x enumC0184x2 = EnumC0184x.CLOSING;
        androidx.camera.view.i iVar = androidx.camera.view.i.a;
        if (enumC0184x == enumC0184x2 || enumC0184x == EnumC0184x.CLOSED || enumC0184x == EnumC0184x.RELEASING || enumC0184x == EnumC0184x.RELEASED) {
            n(iVar);
            if (this.b) {
                this.b = false;
                androidx.camera.core.impl.utils.futures.d dVar = (androidx.camera.core.impl.utils.futures.d) this.f;
                if (dVar != null) {
                    dVar.cancel(false);
                    this.f = null;
                    return;
                }
                return;
            }
            return;
        }
        if ((enumC0184x == EnumC0184x.OPENING || enumC0184x == EnumC0184x.OPEN || enumC0184x == EnumC0184x.PENDING_OPEN) && !this.b) {
            n(iVar);
            ArrayList arrayList = new ArrayList();
            InterfaceC0183w interfaceC0183w = (InterfaceC0183w) this.c;
            androidx.camera.core.impl.utils.futures.d dVarC = androidx.camera.core.impl.utils.futures.d.c(Y5.b(new T(this, interfaceC0183w, arrayList, 2)));
            androidx.camera.view.b bVar = new androidx.camera.view.b(this);
            androidx.camera.core.impl.utils.executor.a aVarA = com.google.android.gms.internal.mlkit_vision_barcode.T.a();
            dVarC.getClass();
            androidx.camera.core.impl.utils.futures.b bVarF = androidx.camera.core.impl.utils.futures.i.f(dVarC, bVar, aVarA);
            androidx.camera.view.b bVar2 = new androidx.camera.view.b(this);
            androidx.camera.core.impl.utils.futures.b bVarF2 = androidx.camera.core.impl.utils.futures.i.f(bVarF, new com.google.android.gms.auth.api.signin.internal.h(bVar2, 7), com.google.android.gms.internal.mlkit_vision_barcode.T.a());
            this.f = bVarF2;
            com.google.android.gms.internal.appset.e eVar = new com.google.android.gms.internal.appset.e(this, arrayList, interfaceC0183w);
            bVarF2.a(new androidx.camera.core.impl.utils.futures.h(0, bVarF2, eVar), com.google.android.gms.internal.mlkit_vision_barcode.T.a());
            this.b = true;
        }
    }

    public void n(androidx.camera.view.i iVar) {
        synchronized (this) {
            try {
                if (((androidx.camera.view.i) this.d).equals(iVar)) {
                    return;
                }
                this.d = iVar;
                Objects.toString(iVar);
                AbstractC3053s1.f(3, "StreamStateObserver");
                ((androidx.lifecycle.Y) this.a).j(iVar);
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public void o(ConnectionResult connectionResult) {
        com.google.android.gms.common.api.internal.n nVar = (com.google.android.gms.common.api.internal.n) ((C1647e) this.f).j.get((C1643a) this.d);
        if (nVar != null) {
            nVar.j(connectionResult);
        }
    }

    @Override // androidx.camera.core.impl.InterfaceC0159a0
    public void onError(Throwable th) {
        androidx.camera.core.impl.utils.futures.d dVar = (androidx.camera.core.impl.utils.futures.d) this.f;
        if (dVar != null) {
            dVar.cancel(false);
            this.f = null;
        }
        n(androidx.camera.view.i.a);
    }

    public void p(HashMap map, String str) {
        AbstractC2270kd.f.execute(new androidx.core.provider.k(this, str, map, 5));
    }

    public void q(String str, String str2) {
        com.google.android.gms.ads.internal.util.A.l(str);
        if (((InterfaceC2529qe) this.a) != null) {
            HashMap map = new HashMap();
            map.put("message", str);
            map.put("action", str2);
            p(map, "onError");
        }
    }

    public void r(boolean z) {
        IntentFilter intentFilter = new IntentFilter("com.android.vending.billing.PURCHASES_UPDATED");
        IntentFilter intentFilter2 = new IntentFilter("com.android.vending.billing.LOCAL_BROADCAST_PURCHASES_UPDATED");
        intentFilter2.addAction("com.android.vending.billing.ALTERNATIVE_BILLING");
        this.b = z;
        ((com.android.billingclient.api.C) this.f).a((Context) this.c, intentFilter2);
        if (!this.b) {
            ((com.android.billingclient.api.C) this.e).a((Context) this.c, intentFilter);
            return;
        }
        com.android.billingclient.api.C c = (com.android.billingclient.api.C) this.e;
        Context context = (Context) this.c;
        synchronized (c) {
            try {
                if (c.b) {
                    return;
                }
                if (Build.VERSION.SDK_INT >= 33) {
                    context.registerReceiver(c, intentFilter, "com.google.android.finsky.permission.PLAY_BILLING_LIBRARY_BROADCAST", null, true != c.c ? 4 : 2);
                } else {
                    context.registerReceiver(c, intentFilter, "com.google.android.finsky.permission.PLAY_BILLING_LIBRARY_BROADCAST", null);
                }
                c.b = true;
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public void s(InterfaceC2529qe interfaceC2529qe, C1896bt c1896bt) {
        if (interfaceC2529qe == null) {
            q("adWebview missing", "onLMDShow");
            return;
        }
        this.a = interfaceC2529qe;
        if (!this.b && !t(interfaceC2529qe.getContext())) {
            q("LMDOverlay not bound", "on_play_store_bind");
            return;
        }
        boolean zBooleanValue = ((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.xb)).booleanValue();
        String str = c1896bt.b;
        if (zBooleanValue) {
            this.d = str;
        }
        if (((androidx.webkit.internal.p) this.f) == null) {
            this.f = new androidx.webkit.internal.p(this, 15);
        }
        Sq sq = (Sq) this.e;
        if (sq != null) {
            androidx.webkit.internal.p pVar = (androidx.webkit.internal.p) this.f;
            C2158ht c2158ht = (C2158ht) sq.a;
            Tm tm = c2158ht.a;
            if (tm == null) {
                C2158ht.c.a("error: %s", "Play Store not found.");
            } else if (C2158ht.c(pVar, "Failed to apply OverlayDisplayShowRequest: missing appId and sessionToken.", Arrays.asList(null, str))) {
                tm.c(new RunnableC2286kt(tm, new com.google.android.gms.internal.ads.C(c2158ht, c1896bt, pVar, 9), 1));
            }
        }
    }

    public synchronized boolean t(Context context) {
        if (!AbstractC2415nt.a(context)) {
            return false;
        }
        try {
            Context applicationContext = context.getApplicationContext();
            if (applicationContext != null) {
                context = applicationContext;
            }
            this.e = new Sq(new C2158ht(context));
        } catch (NullPointerException e) {
            com.google.android.gms.ads.internal.util.A.l("Error connecting LMD Overlay service");
            com.google.android.gms.ads.internal.j.C.h.h("LastMileDeliveryOverlay.bindLastMileDeliveryService", e);
        }
        if (((Sq) this.e) == null) {
            this.b = false;
            return false;
        }
        if (((androidx.webkit.internal.p) this.f) == null) {
            this.f = new androidx.webkit.internal.p(this, 15);
        }
        this.b = true;
        return true;
    }

    public C1982dt u() {
        String str;
        String str2 = null;
        if (!((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.xb)).booleanValue() || TextUtils.isEmpty((String) this.d)) {
            String str3 = (String) this.c;
            if (str3 != null) {
                str2 = str3;
                str = null;
            } else {
                q("Missing session token and/or appId", "onLMDupdate");
                str = null;
            }
        } else {
            str = (String) this.d;
        }
        return new C1982dt(str2, str);
    }

    public p0(Map class2ContextualFactory, Map polyBase2Serializers, Map polyBase2DefaultSerializerProvider, Map polyBase2NamedSerializers, Map polyBase2DefaultDeserializerProvider, boolean z) {
        Intrinsics.checkNotNullParameter(class2ContextualFactory, "class2ContextualFactory");
        Intrinsics.checkNotNullParameter(polyBase2Serializers, "polyBase2Serializers");
        Intrinsics.checkNotNullParameter(polyBase2DefaultSerializerProvider, "polyBase2DefaultSerializerProvider");
        Intrinsics.checkNotNullParameter(polyBase2NamedSerializers, "polyBase2NamedSerializers");
        Intrinsics.checkNotNullParameter(polyBase2DefaultDeserializerProvider, "polyBase2DefaultDeserializerProvider");
        this.c = class2ContextualFactory;
        this.d = polyBase2Serializers;
        this.a = polyBase2DefaultSerializerProvider;
        this.e = polyBase2NamedSerializers;
        this.f = polyBase2DefaultDeserializerProvider;
        this.b = z;
    }

    public p0() {
        this.c = new HashMap();
        this.d = new HashMap();
        this.a = new HashMap();
        this.e = new HashMap();
        this.f = new HashMap();
    }
}
