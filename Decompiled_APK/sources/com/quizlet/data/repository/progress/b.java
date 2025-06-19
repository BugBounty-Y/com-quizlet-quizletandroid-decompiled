package com.quizlet.data.repository.progress;

import android.content.res.Resources;
import android.os.Handler;
import android.os.Looper;
import androidx.camera.camera2.internal.RunnableC0141s;
import androidx.work.impl.model.e;
import androidx.work.impl.model.v;
import assistantMode.refactored.types.Task;
import assistantMode.refactored.types.TaskProgress;
import assistantMode.refactored.types.TaskWithProgress;
import assistantMode.refactored.types.TotalProgress;
import assistantMode.utils.h;
import com.google.android.gms.ads.internal.j;
import com.google.android.gms.internal.ads.C1944cy;
import com.google.android.gms.internal.ads.C2377my;
import com.google.android.gms.internal.ads.C2420ny;
import com.google.android.gms.internal.ads.C2549qy;
import com.google.android.gms.internal.ads.C2591ry;
import com.google.android.gms.internal.ads.C2634sy;
import com.google.android.gms.internal.ads.Gx;
import com.google.android.gms.internal.ads.Ix;
import com.google.android.gms.internal.ads.Pv;
import com.google.android.gms.internal.ads.Zx;
import com.google.android.gms.internal.mlkit_vision_document_scanner.N6;
import com.onetrust.otpublishers.headless.Internal.Log.OTLogger;
import com.onetrust.otpublishers.headless.Internal.Network.d;
import com.onetrust.otpublishers.headless.Public.OTCallback;
import com.onetrust.otpublishers.headless.Public.OTPublishersHeadlessSDK;
import com.onetrust.otpublishers.headless.Public.Response.OTResponse;
import com.onetrust.otpublishers.headless.Public.Response.OTResponseType;
import com.quizlet.quizletandroid.R;
import com.quizlet.studiablemodels.StudiableTaskProgress;
import com.quizlet.studiablemodels.StudiableTotalProgress;
import java.security.GeneralSecurityException;
import java.util.HashMap;
import java.util.Iterator;
import java.util.concurrent.TimeUnit;
import kotlin.collections.CollectionsKt;
import kotlin.collections.K;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import okhttp3.H;
import org.json.JSONException;
import org.json.JSONObject;
import retrofit2.InterfaceC5179d;
import retrofit2.InterfaceC5182g;

/* loaded from: classes2.dex */
public final class b implements Pv, InterfaceC5182g {
    public final Object a;
    public final Object b;
    public Object c;
    public Object d;

    public /* synthetic */ b(Object obj, Object obj2, Object obj3, Object obj4) {
        this.a = obj2;
        this.b = obj3;
        this.c = obj4;
        this.d = obj;
    }

    public void a(String str, String str2) {
        this.d = ((String) this.d) + (((String) this.d).length() == 0 ? "?" : "&") + str + '=' + str2;
    }

    public StudiableTaskProgress b() {
        TaskProgress taskProgress;
        com.quizlet.quizletandroid.ui.studymodes.assistant.studyengine.b bVar = (com.quizlet.quizletandroid.ui.studymodes.assistant.studyengine.b) this.a;
        Object obj = null;
        if (!bVar.b()) {
            return null;
        }
        assistantMode.refactored.interfaces.a aVar = bVar.c;
        if (aVar == null) {
            Intrinsics.m("studyEngine");
            throw null;
        }
        assistantMode.refactored.interfaces.b bVar2 = ((assistantMode.refactored.c) aVar).b;
        if (!(bVar2 instanceof assistantMode.stepGenerators.b)) {
            throw new IllegalStateException(("TasksWithProgress cannot be created using generator: " + bVar2 + " in getCurrentTaskProgress").toString());
        }
        assistantMode.stepGenerators.b bVar3 = (assistantMode.stepGenerators.b) bVar2;
        assistantMode.stepGenerators.types.b bVar4 = bVar3.v;
        Task task = bVar4 == null ? (Task) CollectionsKt.L(bVar3.q) : bVar4.g;
        if (task == null) {
            h hVar = bVar3.c;
            taskProgress = new TaskProgress(hVar.a.size(), hVar.a.size());
        } else {
            Iterator it2 = bVar3.h().iterator();
            while (true) {
                if (!it2.hasNext()) {
                    break;
                }
                Object next = it2.next();
                if (Intrinsics.b(((TaskWithProgress) next).b, task)) {
                    obj = next;
                    break;
                }
            }
            Intrinsics.d(obj);
            taskProgress = ((TaskWithProgress) obj).c;
        }
        Intrinsics.checkNotNullParameter(taskProgress, "<this>");
        return new StudiableTaskProgress(taskProgress.a, taskProgress.b);
    }

    /* JADX WARN: Removed duplicated region for block: B:119:0x02f1  */
    @Override // com.google.android.gms.internal.ads.Pv
    /* renamed from: c */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void mo15c(java.lang.Object r26) throws java.net.URISyntaxException {
        /*
            Method dump skipped, instructions count: 1016
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.repository.progress.b.mo15c(java.lang.Object):void");
    }

    /* JADX WARN: Removed duplicated region for block: B:36:0x00a3  */
    /* JADX WARN: Removed duplicated region for block: B:37:0x00a6  */
    /* JADX WARN: Removed duplicated region for block: B:41:0x00bf  */
    /* JADX WARN: Removed duplicated region for block: B:79:0x016b  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public com.quizlet.studiablemodels.StudiableStep d(java.util.ArrayList r8, boolean r9) {
        /*
            Method dump skipped, instructions count: 445
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.repository.progress.b.d(java.util.ArrayList, boolean):com.quizlet.studiablemodels.StudiableStep");
    }

    public StudiableTotalProgress e() {
        com.quizlet.quizletandroid.ui.studymodes.assistant.studyengine.b bVar = (com.quizlet.quizletandroid.ui.studymodes.assistant.studyengine.b) this.a;
        if (bVar.b()) {
            try {
                assistantMode.refactored.interfaces.a aVar = bVar.c;
                if (aVar == null) {
                    Intrinsics.m("studyEngine");
                    throw null;
                }
                assistantMode.refactored.c cVar = (assistantMode.refactored.c) aVar;
                if (cVar.f == null) {
                    cVar.a(System.currentTimeMillis(), K.a, false);
                }
                TotalProgress totalProgress = cVar.f;
                if (totalProgress != null) {
                    return N6.a(totalProgress);
                }
                throw new IllegalStateException("mTotalProgress must not be null");
            } catch (IllegalStateException unused) {
            }
        }
        return null;
    }

    @Override // retrofit2.InterfaceC5182g
    public void f(InterfaceC5179d interfaceC5179d, Throwable th) {
        OTLogger.c("NetworkRequestHandler", 6, " network call response error out = " + th.getMessage());
        ((OTCallback) this.b).onFailure(new OTResponse(OTResponseType.OT_ERROR, 7, ((d) this.d).a.getResources().getString(R.string.err_ott_callback_failure), ""));
    }

    public void g(Gx gx) throws GeneralSecurityException {
        gx.getClass();
        C2549qy c2549qy = new C2549qy(C2377my.class, gx.a);
        HashMap map = (HashMap) this.b;
        if (!map.containsKey(c2549qy)) {
            map.put(c2549qy, gx);
            return;
        }
        Gx gx2 = (Gx) map.get(c2549qy);
        if (!gx2.equals(gx) || !gx.equals(gx2)) {
            throw new GeneralSecurityException("Attempt to register non-equal parser for already existing object of type: ".concat(c2549qy.toString()));
        }
    }

    public void h(Ix ix) throws GeneralSecurityException {
        C2591ry c2591ry = new C2591ry(ix.a, C2377my.class);
        HashMap map = (HashMap) this.a;
        if (!map.containsKey(c2591ry)) {
            map.put(c2591ry, ix);
            return;
        }
        Ix ix2 = (Ix) map.get(c2591ry);
        if (!ix2.equals(ix) || !ix.equals(ix2)) {
            throw new GeneralSecurityException("Attempt to register non-equal serializer for already existing object of type: ".concat(c2591ry.toString()));
        }
    }

    public void i(Zx zx) throws GeneralSecurityException {
        zx.getClass();
        C2549qy c2549qy = new C2549qy(C2420ny.class, zx.a);
        HashMap map = (HashMap) this.d;
        if (!map.containsKey(c2549qy)) {
            map.put(c2549qy, zx);
            return;
        }
        Zx zx2 = (Zx) map.get(c2549qy);
        if (!zx2.equals(zx) || !zx.equals(zx2)) {
            throw new GeneralSecurityException("Attempt to register non-equal parser for already existing object of type: ".concat(c2549qy.toString()));
        }
    }

    public void j(C1944cy c1944cy) throws GeneralSecurityException {
        C2591ry c2591ry = new C2591ry(c1944cy.a, C2420ny.class);
        HashMap map = (HashMap) this.c;
        if (!map.containsKey(c2591ry)) {
            map.put(c2591ry, c1944cy);
            return;
        }
        C1944cy c1944cy2 = (C1944cy) map.get(c2591ry);
        if (!c1944cy2.equals(c1944cy) || !c1944cy.equals(c1944cy2)) {
            throw new GeneralSecurityException("Attempt to register non-equal serializer for already existing object of type: ".concat(c2591ry.toString()));
        }
    }

    @Override // retrofit2.InterfaceC5182g
    public void k(InterfaceC5179d interfaceC5179d, retrofit2.K k) throws Resources.NotFoundException {
        OTResponse oTResponse;
        String str = (String) k.b;
        OTLogger.c("NetworkRequestHandler", 4, " OTT response? = " + str);
        H h = k.a;
        long j = h.l - h.k;
        OTLogger.c("OneTrust", 3, String.format("%s %d.%d s", "Time taken for OT SDK setup data fetch: ", Long.valueOf(TimeUnit.MILLISECONDS.toSeconds(j)), Long.valueOf(j % 1000)));
        d dVar = (d) this.d;
        String string = dVar.a.getResources().getString(R.string.warn_ot_failure);
        if (com.onetrust.otpublishers.headless.Internal.a.j(str)) {
            oTResponse = new OTResponse(OTResponseType.OT_ERROR, 2, string.replace("SDK_VERSION", (String) this.a), "");
        } else {
            try {
                JSONObject jSONObject = new JSONObject(str);
                if (jSONObject.has("culture") && jSONObject.has("domain") && jSONObject.has("profile")) {
                    oTResponse = null;
                } else {
                    OTLogger.c("OneTrust", 6, "SDK Initialization failed, Cannot parse the data received from Server because it is corrupted");
                    oTResponse = new OTResponse(OTResponseType.OT_ERROR, 7, "SDK Initialization failed, Cannot parse the data received from Server because it is corrupted", "");
                }
            } catch (JSONException e) {
                OTLogger.c("OneTrust", 6, "SDK Initialization failed, Cannot parse the data received from Server because it is corrupted" + e.toString());
                oTResponse = new OTResponse(OTResponseType.OT_ERROR, 7, "SDK Initialization failed, Cannot parse the data received from Server because it is corrupted", "");
            }
        }
        OTCallback oTCallback = (OTCallback) this.b;
        if (oTResponse != null) {
            oTCallback.onFailure(oTResponse);
        } else {
            new Thread(new RunnableC0141s(dVar, k, str, oTCallback, new Handler(Looper.getMainLooper()), (OTPublishersHeadlessSDK) this.c)).start();
        }
    }

    @Override // com.google.android.gms.internal.ads.Pv
    public void zza(Throwable th) {
        j.C.h.h("OpenGmsgHandler.attributionReportingManager", th);
    }

    public b() {
        this.a = new HashMap();
        this.b = new HashMap();
        this.c = new HashMap();
        this.d = new HashMap();
    }

    public b(C2634sy c2634sy) {
        this.a = new HashMap(c2634sy.a);
        this.b = new HashMap(c2634sy.b);
        this.c = new HashMap(c2634sy.c);
        this.d = new HashMap(c2634sy.d);
    }

    public b(androidx.work.impl.model.c userProperties, com.quizlet.features.onboarding.survey.j onboardingSurveyFeatureUseCase, e onboardingFlashcardsFeatureUseCase, v qPlusUpsellUseCase) {
        Intrinsics.checkNotNullParameter(userProperties, "userProperties");
        Intrinsics.checkNotNullParameter(onboardingSurveyFeatureUseCase, "onboardingSurveyFeatureUseCase");
        Intrinsics.checkNotNullParameter(onboardingFlashcardsFeatureUseCase, "onboardingFlashcardsFeatureUseCase");
        Intrinsics.checkNotNullParameter(qPlusUpsellUseCase, "qPlusUpsellUseCase");
        this.a = userProperties;
        this.b = onboardingSurveyFeatureUseCase;
        this.c = onboardingFlashcardsFeatureUseCase;
        this.d = qPlusUpsellUseCase;
    }

    public b(com.quizlet.remote.model.progress.e remoteRepository, com.quizlet.data.repository.folderwithcreator.e localRepository, org.slf4j.b logger, com.quizlet.data.connectivity.a networkStatus) {
        Intrinsics.checkNotNullParameter(remoteRepository, "remoteRepository");
        Intrinsics.checkNotNullParameter(localRepository, "localRepository");
        Intrinsics.checkNotNullParameter(logger, "logger");
        Intrinsics.checkNotNullParameter(networkStatus, "networkStatus");
        this.a = remoteRepository;
        this.b = localRepository;
        this.c = logger;
        this.d = networkStatus;
    }

    public b(com.quizlet.quizletandroid.ui.studymodes.assistant.studyengine.b studyEngine, kotlinx.coroutines.scheduling.e defaultDispatcher) {
        com.quizlet.qutils.i18n.a localeUtil = com.quizlet.qutils.i18n.a.a;
        com.quizlet.features.infra.basestudy.utils.c studiableDataFactory = com.quizlet.features.infra.basestudy.utils.c.a;
        Intrinsics.checkNotNullParameter(studyEngine, "studyEngine");
        Intrinsics.checkNotNullParameter(localeUtil, "localeUtil");
        Intrinsics.checkNotNullParameter(studiableDataFactory, "studiableDataFactory");
        Intrinsics.checkNotNullParameter(defaultDispatcher, "defaultDispatcher");
        this.a = studyEngine;
        this.b = defaultDispatcher;
    }

    public b(KSerializer serializer) {
        Intrinsics.checkNotNullParameter(serializer, "serializer");
        this.c = "";
        this.d = "";
        this.a = serializer;
        this.b = serializer.getDescriptor().a();
    }
}
