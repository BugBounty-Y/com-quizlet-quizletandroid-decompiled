package androidx.credentials.playservices.controllers.BeginSignIn;

import android.app.Activity;
import android.app.ActivityManager;
import android.content.Context;
import android.os.StatFs;
import androidx.compose.animation.core.J0;
import androidx.compose.runtime.internal.j;
import androidx.compose.ui.text.C0981a;
import androidx.credentials.exceptions.GetCredentialException;
import androidx.credentials.playservices.controllers.GetSignInIntent.CredentialProviderGetSignInIntentController;
import androidx.datastore.core.P;
import androidx.datastore.core.a0;
import androidx.datastore.core.n0;
import androidx.glance.session.C1231i;
import androidx.paging.a1;
import androidx.work.impl.model.i;
import assistantMode.enums.k;
import assistantMode.refactored.types.RevealSelfAssessmentQuestion;
import assistantMode.refactored.types.flashcards.FlashcardsSubmitAction;
import assistantMode.types.B;
import assistantMode.types.C1454a;
import assistantMode.types.C1457d;
import assistantMode.types.aliases.ExperimentConfiguration;
import com.google.android.gms.ads.internal.client.C1608n;
import com.google.android.gms.internal.mlkit_vision_camera.A2;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3410x2;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3418z2;
import com.mayakapps.kache.A;
import com.mayakapps.kache.C4034c;
import com.mayakapps.kache.x;
import com.onetrust.otpublishers.headless.UI.fragment.s;
import com.quizlet.remote.model.notes.e;
import com.snowplowanalytics.snowplow.network.f;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.Array;
import java.lang.reflect.Field;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.C4950i;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;
import kotlin.jvm.internal.r;
import kotlinx.coroutines.InterfaceC5025j0;
import kotlinx.coroutines.channels.t;
import kotlinx.coroutines.channels.u;
import kotlinx.coroutines.flow.d0;
import okhttp3.internal.connection.g;
import okhttp3.n;
import org.json.JSONObject;

/* loaded from: classes.dex */
public final class c extends r implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ c(Object obj, int i) {
        super(1);
        this.a = i;
        this.b = obj;
    }

    /* JADX WARN: Type inference failed for: r12v7, types: [java.lang.Object, java.util.Map] */
    /* JADX WARN: Type inference failed for: r15v3, types: [java.lang.Object, java.util.Map] */
    /* JADX WARN: Type inference failed for: r3v4, types: [kotlin.jvm.functions.Function1, kotlin.jvm.internal.r] */
    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) throws IllegalAccessException, IllegalArgumentException, UnsupportedEncodingException {
        Object next;
        com.snowplowanalytics.snowplow.network.d fVar;
        com.snowplowanalytics.snowplow.network.d fVar2;
        com.snowplowanalytics.snowplow.network.d fVar3;
        int i = 2;
        int i2 = 1;
        boolean zG = false;
        Object obj2 = null;
        com.snowplowanalytics.snowplow.network.d fVar4 = null;
        switch (this.a) {
            case 0:
                GetCredentialException e = (GetCredentialException) obj;
                Intrinsics.checkNotNullParameter(e, "e");
                CredentialProviderBeginSignInController credentialProviderBeginSignInController = (CredentialProviderBeginSignInController) this.b;
                credentialProviderBeginSignInController.g().execute(new b(credentialProviderBeginSignInController, e, zG ? 1 : 0));
                return Unit.a;
            case 1:
                GetCredentialException e2 = (GetCredentialException) obj;
                Intrinsics.checkNotNullParameter(e2, "e");
                CredentialProviderGetSignInIntentController credentialProviderGetSignInIntentController = (CredentialProviderGetSignInIntentController) this.b;
                credentialProviderGetSignInIntentController.h().execute(new androidx.credentials.playservices.controllers.GetSignInIntent.b(credentialProviderGetSignInIntentController, e2, 0));
                return Unit.a;
            case 2:
                Throwable th = (Throwable) obj;
                P p = (P) this.b;
                if (th != null) {
                    p.h.w(new a0(th));
                }
                if (p.j.isInitialized()) {
                    ((n0) p.j.getValue()).close();
                }
                return Unit.a;
            case 3:
                ((t) ((u) this.b)).o(null);
                return Unit.a;
            case 4:
                C1231i c1231i = (C1231i) this.b;
                synchronized (c1231i.c) {
                    c1231i.d = 5;
                    c1231i.f = null;
                }
                return Unit.a;
            case 5:
                ((InterfaceC5025j0) this.b).j(null);
                return Unit.a;
            case 6:
                ((d0) ((e) this.b).c).h(null);
                return Unit.a;
            case 7:
                ((a1) this.b).a.k(null, false);
                return Unit.a;
            case 8:
                app.cash.sqldelight.driver.android.a cursor = (app.cash.sqldelight.driver.android.a) obj;
                Intrinsics.checkNotNullParameter(cursor, "cursor");
                if (!Boolean.valueOf(cursor.a.moveToNext()).booleanValue()) {
                    return new app.cash.sqldelight.db.c(null);
                }
                J0 j0 = (J0) this.b;
                Object objInvoke = ((r) j0.b).invoke(cursor);
                if (!Boolean.valueOf(cursor.a.moveToNext()).booleanValue()) {
                    return new app.cash.sqldelight.db.c(objInvoke);
                }
                throw new IllegalStateException(("ResultSet returned more than 1 row for " + j0).toString());
            case 9:
                org.koin.core.module.a module = (org.koin.core.module.a) obj;
                Intrinsics.checkNotNullParameter(module, "$this$module");
                org.koin.core.definition.b beanDefinition = new org.koin.core.definition.b(org.koin.core.registry.a.c, K.a(ExperimentConfiguration.class), null, new C0981a((ExperimentConfiguration) this.b, 6), org.koin.core.definition.c.a, kotlin.collections.K.a);
                Intrinsics.checkNotNullParameter(beanDefinition, "beanDefinition");
                org.koin.core.instance.c factory = new org.koin.core.instance.c(beanDefinition);
                module.b(factory);
                Intrinsics.checkNotNullParameter(module, "module");
                Intrinsics.checkNotNullParameter(factory, "factory");
                return Unit.a;
            case 10:
                k it2 = (k) obj;
                Intrinsics.checkNotNullParameter(it2, "it");
                return Boolean.valueOf(!((Set) ((j) this.b).d).contains(it2));
            case 11:
                RevealSelfAssessmentQuestion it3 = (RevealSelfAssessmentQuestion) obj;
                Intrinsics.checkNotNullParameter(it3, "it");
                return Boolean.valueOf(Intrinsics.b(it3, ((FlashcardsSubmitAction) this.b).a));
            case 12:
                String str = (String) obj;
                Object objOpt = ((JSONObject) this.b).opt(str);
                if (objOpt == null) {
                    return null;
                }
                try {
                    return URLEncoder.encode(str, "UTF-8") + '=' + URLEncoder.encode(objOpt.toString(), "UTF-8");
                } catch (Exception unused) {
                    return null;
                }
            case 13:
                A OkioFileKache = (A) obj;
                Intrinsics.checkNotNullParameter(OkioFileKache, "$this$OkioFileKache");
                C4034c c4034c = (C4034c) this.b;
                x xVar = c4034c.a;
                OkioFileKache.getClass();
                Intrinsics.checkNotNullParameter(xVar, "<set-?>");
                OkioFileKache.a = xVar;
                kotlinx.coroutines.internal.d dVar = c4034c.b;
                Intrinsics.checkNotNullParameter(dVar, "<set-?>");
                OkioFileKache.b = dVar;
                OkioFileKache.c = c4034c.c;
                OkioFileKache.d = c4034c.d;
                return Unit.a;
            case 14:
                String it4 = (String) obj;
                Intrinsics.checkNotNullParameter(it4, "it");
                com.onetrust.otpublishers.headless.UI.viewmodel.d dVarS = ((s) this.b).S();
                if (it4 == null) {
                    dVarS.getClass();
                } else {
                    zG = dVarS.c.g(it4);
                }
                return Boolean.valueOf(zG);
            case 15:
                org.koin.core.module.a module2 = (org.koin.core.module.a) obj;
                Intrinsics.checkNotNullParameter(module2, "$this$module");
                C1608n c1608n = (C1608n) this.b;
                com.quizlet.shared.di.b bVar = new com.quizlet.shared.di.b(c1608n, zG ? 1 : 0);
                org.koin.core.qualifier.a aVar = org.koin.core.registry.a.c;
                org.koin.core.definition.c cVar = org.koin.core.definition.c.a;
                kotlin.collections.K k = kotlin.collections.K.a;
                org.koin.core.definition.b beanDefinition2 = new org.koin.core.definition.b(aVar, K.a(com.quizlet.remote.kmp.a.class), null, bVar, cVar, k);
                Intrinsics.checkNotNullParameter(beanDefinition2, "beanDefinition");
                org.koin.core.instance.c factory2 = new org.koin.core.instance.c(beanDefinition2);
                module2.b(factory2);
                Intrinsics.checkNotNullParameter(module2, "module");
                Intrinsics.checkNotNullParameter(factory2, "factory");
                org.koin.core.definition.b beanDefinition3 = new org.koin.core.definition.b(aVar, K.a(com.quizlet.shared.experimentmanager.a.class), null, new com.quizlet.shared.di.c(c1608n), cVar, k);
                Intrinsics.checkNotNullParameter(beanDefinition3, "beanDefinition");
                org.koin.core.instance.c factory3 = new org.koin.core.instance.c(beanDefinition3);
                module2.b(factory3);
                Intrinsics.checkNotNullParameter(module2, "module");
                Intrinsics.checkNotNullParameter(factory3, "factory");
                org.koin.core.definition.b beanDefinition4 = new org.koin.core.definition.b(aVar, K.a(com.quizlet.local.sqldelight.a.class), null, new com.quizlet.shared.di.b(c1608n, i2), cVar, k);
                Intrinsics.checkNotNullParameter(beanDefinition4, "beanDefinition");
                org.koin.core.instance.c cVar2 = new org.koin.core.instance.c(beanDefinition4);
                module2.b(cVar2);
                AbstractC3418z2.b(new org.koin.core.definition.d(module2, cVar2), new kotlin.reflect.c[]{K.a(com.quizlet.local.sqldelight.a.class), K.a(com.quizlet.local.sqldelight.a.class)});
                org.koin.core.definition.b beanDefinition5 = new org.koin.core.definition.b(aVar, K.a(com.quizlet.shared.eventlogger.a.class), null, new com.quizlet.shared.di.b(c1608n, i), cVar, k);
                Intrinsics.checkNotNullParameter(beanDefinition5, "beanDefinition");
                org.koin.core.instance.c factory4 = new org.koin.core.instance.c(beanDefinition5);
                module2.b(factory4);
                Intrinsics.checkNotNullParameter(module2, "module");
                Intrinsics.checkNotNullParameter(factory4, "factory");
                i iVar = (i) c1608n.e;
                Object systemService = ((Context) iVar.b).getSystemService("activity");
                Intrinsics.e(systemService, "null cannot be cast to non-null type android.app.ActivityManager");
                ActivityManager.MemoryInfo memoryInfo = new ActivityManager.MemoryInfo();
                ((ActivityManager) systemService).getMemoryInfo(memoryInfo);
                long j = memoryInfo.totalMem;
                Iterator it5 = iVar.d.entrySet().iterator();
                while (true) {
                    if (it5.hasNext()) {
                        next = it5.next();
                        if (j <= ((Number) ((Map.Entry) next).getKey()).longValue()) {
                        }
                    } else {
                        next = null;
                    }
                }
                Map.Entry entry = (Map.Entry) next;
                com.quizlet.shared.cache.j jVar = new com.quizlet.shared.cache.j(entry != null ? ((Number) entry.getValue()).longValue() : 52428800L);
                String strK = android.support.v4.media.session.a.k(((Context) c1608n.a).getFilesDir().getPath(), "/quizlet_android");
                StatFs statFs = (StatFs) iVar.c;
                long blockCountLong = statFs.getBlockCountLong() * statFs.getBlockSizeLong();
                Iterator it6 = iVar.e.entrySet().iterator();
                while (true) {
                    if (it6.hasNext()) {
                        Object next2 = it6.next();
                        if (blockCountLong <= ((Number) ((Map.Entry) next2).getKey()).longValue()) {
                            obj2 = next2;
                        }
                    }
                }
                Map.Entry entry2 = (Map.Entry) obj2;
                com.quizlet.shared.cache.b bVar2 = new com.quizlet.shared.cache.b(jVar, new com.quizlet.shared.cache.t(strK, entry2 != null ? ((Number) entry2.getValue()).longValue() : 209715200L));
                com.quizlet.shared.di.d dVar2 = new com.quizlet.shared.di.d(bVar2, zG ? 1 : 0);
                org.koin.core.qualifier.a aVar2 = org.koin.core.registry.a.c;
                org.koin.core.definition.c cVar3 = org.koin.core.definition.c.a;
                kotlin.collections.K k2 = kotlin.collections.K.a;
                org.koin.core.definition.b beanDefinition6 = new org.koin.core.definition.b(aVar2, K.a(com.quizlet.shared.cache.j.class), null, dVar2, cVar3, k2);
                Intrinsics.checkNotNullParameter(beanDefinition6, "beanDefinition");
                org.koin.core.instance.c factory5 = new org.koin.core.instance.c(beanDefinition6);
                module2.b(factory5);
                Intrinsics.checkNotNullParameter(module2, "module");
                Intrinsics.checkNotNullParameter(factory5, "factory");
                org.koin.core.definition.b beanDefinition7 = new org.koin.core.definition.b(aVar2, K.a(com.quizlet.shared.cache.t.class), null, new com.quizlet.shared.di.d(bVar2, i2), cVar3, k2);
                Intrinsics.checkNotNullParameter(beanDefinition7, "beanDefinition");
                org.koin.core.instance.c factory6 = new org.koin.core.instance.c(beanDefinition7);
                module2.b(factory6);
                Intrinsics.checkNotNullParameter(module2, "module");
                Intrinsics.checkNotNullParameter(factory6, "factory");
                org.koin.core.definition.b beanDefinition8 = new org.koin.core.definition.b(aVar2, K.a(String.class), AbstractC3410x2.b("QUIZLET_API_BASE_URL_OVERRIDE"), new com.quizlet.shared.di.c(i), cVar3, k2);
                Intrinsics.checkNotNullParameter(beanDefinition8, "beanDefinition");
                org.koin.core.instance.c factory7 = new org.koin.core.instance.c(beanDefinition8);
                module2.b(factory7);
                Intrinsics.checkNotNullParameter(module2, "module");
                Intrinsics.checkNotNullParameter(factory7, "factory");
                org.koin.core.module.a aVar3 = assistantMode.di.c.a;
                module2.a(A2.b(new assistantMode.di.b(i2, i2)));
                return Unit.a;
            case 16:
                com.quizlet.quizletandroid.ui.activitycenter.views.i iVar2 = (com.quizlet.quizletandroid.ui.activitycenter.views.i) this.b;
                ((g) iVar2.b).cancel();
                boolean z = ((g) iVar2.b).o;
                return Unit.a;
            case 17:
                com.quizlet.local.ormlite.models.term.b bVar3 = (com.quizlet.local.ormlite.models.term.b) this.b;
                ((g) bVar3.b).cancel();
                boolean z2 = ((g) bVar3.b).o;
                return Unit.a;
            case 18:
                com.snowplowanalytics.core.emitter.a emitter = (com.snowplowanalytics.core.emitter.a) obj;
                Intrinsics.checkNotNullParameter(emitter, "emitter");
                com.snowplowanalytics.core.tracker.k kVar = (com.snowplowanalytics.core.tracker.k) this.b;
                com.snowplowanalytics.snowplow.network.c method = kVar.b().c();
                emitter.getClass();
                Intrinsics.checkNotNullParameter(method, "method");
                emitter.t = method;
                EnumSet enumSet = emitter.n;
                String str2 = emitter.g;
                boolean z3 = emitter.e;
                boolean z4 = emitter.b;
                Activity activity = emitter.f;
                if (!z3 && z4) {
                    Integer num = emitter.w;
                    if (num != null) {
                        int iIntValue = num.intValue();
                        if (str2 == null) {
                            Intrinsics.m("uri");
                            throw null;
                        }
                        com.snowplowanalytics.snowplow.network.e eVar = new com.snowplowanalytics.snowplow.network.e(str2, activity);
                        eVar.a(emitter.t);
                        eVar.b(enumSet);
                        eVar.e = iIntValue;
                        eVar.h = emitter.x;
                        eVar.f = emitter.l;
                        eVar.g = emitter.j;
                        eVar.i = emitter.z;
                        eVar.j = emitter.C;
                        fVar3 = new f(eVar);
                    } else {
                        fVar3 = null;
                    }
                    emitter.d(fVar3);
                }
                com.snowplowanalytics.snowplow.network.g security = kVar.b().g();
                Intrinsics.checkNotNullParameter(security, "security");
                emitter.v = security;
                if (!z3 && z4) {
                    Integer num2 = emitter.w;
                    if (num2 != null) {
                        int iIntValue2 = num2.intValue();
                        if (str2 == null) {
                            Intrinsics.m("uri");
                            throw null;
                        }
                        com.snowplowanalytics.snowplow.network.e eVar2 = new com.snowplowanalytics.snowplow.network.e(str2, activity);
                        eVar2.a(emitter.t);
                        eVar2.b(enumSet);
                        eVar2.e = iIntValue2;
                        eVar2.h = emitter.x;
                        eVar2.f = emitter.l;
                        eVar2.g = emitter.j;
                        eVar2.i = emitter.z;
                        eVar2.j = emitter.C;
                        fVar2 = new f(eVar2);
                    } else {
                        fVar2 = null;
                    }
                    emitter.d(fVar2);
                }
                emitter.d(kVar.b().d());
                String strA = kVar.b().a();
                emitter.x = strA;
                if (!z3 && z4) {
                    Integer num3 = emitter.w;
                    if (num3 != null) {
                        int iIntValue3 = num3.intValue();
                        if (str2 == null) {
                            Intrinsics.m("uri");
                            throw null;
                        }
                        com.snowplowanalytics.snowplow.network.e eVar3 = new com.snowplowanalytics.snowplow.network.e(str2, activity);
                        eVar3.a(emitter.t);
                        eVar3.b(enumSet);
                        eVar3.e = iIntValue3;
                        eVar3.h = strA;
                        eVar3.f = emitter.l;
                        eVar3.g = emitter.j;
                        eVar3.i = emitter.z;
                        eVar3.j = emitter.C;
                        fVar = new f(eVar3);
                    } else {
                        fVar = null;
                    }
                    emitter.d(fVar);
                }
                okhttp3.A aE = kVar.b().e();
                if (!z4) {
                    emitter.l = aE;
                }
                n nVarF = kVar.b().f();
                if (!z4) {
                    emitter.j = nVarF;
                }
                Integer numJ = kVar.b().j();
                emitter.w = numJ;
                if (!z3 && z4) {
                    if (str2 == null) {
                        Intrinsics.m("uri");
                        throw null;
                    }
                    com.snowplowanalytics.snowplow.network.e eVar4 = new com.snowplowanalytics.snowplow.network.e(str2, activity);
                    eVar4.a(emitter.t);
                    eVar4.b(enumSet);
                    eVar4.e = numJ.intValue();
                    eVar4.h = emitter.x;
                    eVar4.f = emitter.l;
                    eVar4.g = emitter.j;
                    eVar4.i = emitter.z;
                    eVar4.j = emitter.C;
                    emitter.d(new f(eVar4));
                }
                emitter.q = kVar.a().e();
                com.snowplowanalytics.snowplow.emitter.a option = kVar.a().a();
                Intrinsics.checkNotNullParameter(option, "option");
                if (!emitter.c.get()) {
                    emitter.u = option;
                }
                emitter.s = kVar.a().c();
                emitter.r = kVar.a().b();
                int iM = kVar.a().m();
                if (!z4) {
                    emitter.k = iM;
                }
                kVar.a().j();
                Map mapD = kVar.a().d();
                AtomicReference atomicReference = emitter.A;
                if (mapD == null) {
                    mapD = new HashMap();
                }
                atomicReference.set(mapD);
                boolean zL = kVar.a().l();
                emitter.z = zL;
                if (!z3 && z4) {
                    AtomicReference atomicReference2 = emitter.y;
                    if (((com.snowplowanalytics.snowplow.network.d) atomicReference2.get()) instanceof f) {
                        com.snowplowanalytics.snowplow.network.d dVar3 = (com.snowplowanalytics.snowplow.network.d) atomicReference2.get();
                        Intrinsics.e(dVar3, "null cannot be cast to non-null type com.snowplowanalytics.snowplow.network.OkHttpNetworkConnection");
                        ((f) dVar3).e = zL;
                    }
                }
                Map mapH = kVar.b().h();
                emitter.C = mapH;
                if (!z3 && z4) {
                    Integer num4 = emitter.w;
                    if (num4 != null) {
                        int iIntValue4 = num4.intValue();
                        if (str2 == null) {
                            Intrinsics.m("uri");
                            throw null;
                        }
                        com.snowplowanalytics.snowplow.network.e eVar5 = new com.snowplowanalytics.snowplow.network.e(str2, activity);
                        eVar5.a(emitter.t);
                        eVar5.b(enumSet);
                        eVar5.e = iIntValue4;
                        eVar5.h = emitter.x;
                        eVar5.f = emitter.l;
                        eVar5.g = emitter.j;
                        eVar5.i = emitter.z;
                        eVar5.j = mapH;
                        fVar4 = new f(eVar5);
                    }
                    emitter.d(fVar4);
                }
                emitter.B.set(Boolean.valueOf(kVar.a().k()));
                emitter.E = kVar.a().g();
                emitter.D = kVar.a().h();
                return Unit.a;
            case 19:
                ArrayList mViews = (ArrayList) obj;
                Intrinsics.checkNotNullParameter(mViews, "mViews");
                curtains.internal.a aVar4 = ((curtains.internal.b) this.b).b;
                aVar4.addAll(mViews);
                return aVar4;
            case 20:
                Intrinsics.f((Activity) obj, "it");
                Object sCached = ((Field) this.b).get(null);
                Intrinsics.c(sCached, "sCached");
                synchronized (sCached) {
                    int length = Array.getLength(sCached);
                    for (int i3 = 0; i3 < length; i3++) {
                        Array.set(sCached, i3, null);
                    }
                }
                return Unit.a;
            case 21:
                kotlin.reflect.c clazz = (kotlin.reflect.c) obj;
                Intrinsics.checkNotNullParameter(clazz, "clazz");
                return Boolean.valueOf(kotlin.jvm.a.b(clazz).isAssignableFrom(kotlin.jvm.a.b((C4950i) this.b)));
            default:
                assistantMode.types.A a = (assistantMode.types.A) obj;
                Intrinsics.checkNotNullParameter(a, "<name for destructuring parameter 0>");
                return new B(new C1457d((C1454a) this.b, a.a, a.b));
        }
    }
}
