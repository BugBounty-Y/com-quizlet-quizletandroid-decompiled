package androidx.camera.camera2.internal;

import android.hardware.camera2.CameraAccessException;
import android.hardware.camera2.CameraDevice;
import android.os.CancellationSignal;
import androidx.camera.core.impl.DeferrableSurface$SurfaceClosedException;
import androidx.credentials.playservices.CredentialProviderPlayServicesImpl;
import androidx.transition.C1412o;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3242q6;
import com.google.android.gms.internal.mlkit_vision_barcode.Y5;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3347h2;
import com.quizlet.api.model.ApiThreeWrapper;
import com.quizlet.db.data.models.persisted.DBEnteredSetPassword;
import com.quizlet.db.data.models.persisted.DBStudySet;
import com.quizlet.db.data.models.persisted.base.ModelType;
import com.quizlet.remote.exceptions.NetException;
import io.reactivex.rxjava3.internal.operators.observable.C4884c;
import io.reactivex.rxjava3.internal.operators.observable.C4893l;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CancellationException;
import java.util.concurrent.Executor;
import java.util.regex.Pattern;

/* loaded from: classes.dex */
public final /* synthetic */ class j0 implements androidx.concurrent.futures.j, androidx.camera.core.impl.utils.futures.a, com.google.android.gms.tasks.c, com.quizlet.uicommon.ui.common.dialogs.f {
    public final /* synthetic */ Object a;
    public final /* synthetic */ Object b;
    public final /* synthetic */ Object c;
    public final /* synthetic */ Object d;

    public /* synthetic */ j0(k0 k0Var, CameraDevice cameraDevice, androidx.camera.camera2.internal.compat.params.q qVar, List list) {
        this.a = k0Var;
        this.d = cameraDevice;
        this.b = qVar;
        this.c = list;
    }

    public com.quizlet.infra.legacysyncengine.tasks.parse.h a(ApiThreeWrapper apiThreeWrapper) {
        NetException netException;
        NetException netException2;
        final com.quizlet.infra.legacysyncengine.tasks.parse.f fVar = (com.quizlet.infra.legacysyncengine.tasks.parse.f) this.a;
        fVar.getClass();
        if (apiThreeWrapper == null) {
            throw new IllegalStateException("Trying to get result from a missing wrapper, should not be possible");
        }
        com.quizlet.infra.legacysyncengine.net.constants.a aVar = (com.quizlet.infra.legacysyncengine.net.constants.a) this.b;
        int iOrdinal = aVar.ordinal();
        HashMap map = (HashMap) this.c;
        final List list = null;
        ModelType modelType = (ModelType) this.d;
        if (iOrdinal == 1 ? apiThreeWrapper.getResponses() == null : !(iOrdinal == 2 || iOrdinal == 3) || apiThreeWrapper.getResponses() == null || apiThreeWrapper.getResponses().size() <= 0 || map == null || map.get(modelType) == null || ((List) map.get(modelType)).size() != apiThreeWrapper.getResponses().size()) {
            if (apiThreeWrapper.getError() != null) {
                Integer code = apiThreeWrapper.getError().getCode();
                netException2 = com.onetrust.otpublishers.headless.UI.fragment.q.j(code != null ? code.intValue() : 503);
            } else {
                netException2 = null;
            }
            if (netException2 == null) {
                netException2 = new NetException("Sorry, there was an error syncing your data");
                timber.log.c.a(netException2);
            }
            com.quizlet.infra.legacysyncengine.net.request.i iVar = new com.quizlet.infra.legacysyncengine.net.request.i(netException2, null, null);
            Map map2 = Collections.EMPTY_MAP;
            return new com.quizlet.infra.legacysyncengine.tasks.parse.h(map2, map2, iVar, com.quizlet.infra.legacysyncengine.tasks.parse.f.a(apiThreeWrapper));
        }
        if (apiThreeWrapper.getError() != null) {
            Integer code2 = apiThreeWrapper.getError().getCode();
            netException = com.onetrust.otpublishers.headless.UI.fragment.q.j(code2 != null ? code2.intValue() : 503);
        } else {
            netException = null;
        }
        if (map != null && modelType != null) {
            list = (List) map.get(modelType);
        }
        com.jakewharton.rxbinding4.a aVarO = io.reactivex.rxjava3.core.i.o(apiThreeWrapper.getResponses());
        if (0 + 2147483646 > 2147483647L) {
            throw new IllegalArgumentException("Integer overflow");
        }
        C4884c c4884cL = io.reactivex.rxjava3.core.i.y(aVarO, new io.reactivex.rxjava3.internal.operators.observable.g0(), new com.quizlet.infra.legacysyncengine.models.serializers.a(12)).m(new com.quizlet.infra.legacysyncengine.net.e(modelType), SubsamplingScaleImageView.TILE_SIZE_AUTO).l(new com.quizlet.infra.legacysyncengine.models.serializers.a(8));
        io.reactivex.rxjava3.internal.functions.d.a(16, "initialCapacity");
        C4893l c4893l = new C4893l(c4884cL);
        Map map3 = (Map) new io.reactivex.rxjava3.internal.operators.completable.m(c4893l.q(new com.quizlet.infra.legacysyncengine.tasks.parse.c(fVar, modelType, list)), new HashMap(), new com.quizlet.infra.legacysyncengine.tasks.parse.d(fVar)).g(new com.quizlet.infra.legacysyncengine.tasks.parse.d(fVar)).b();
        Map map4 = (list == null || list.size() == 0) ? Collections.EMPTY_MAP : (Map) new io.reactivex.rxjava3.internal.operators.completable.m(c4893l.l(new com.quizlet.infra.legacysyncengine.models.serializers.a(10)), new HashMap(), new com.quizlet.infra.legacysyncengine.tasks.parse.c(fVar, modelType, list)).b();
        if (com.quizlet.infra.legacysyncengine.net.constants.a.c.equals(aVar)) {
            List list2 = (List) map3.get(modelType);
            List list3 = (List) map4.get(modelType);
            int size = list2 == null ? 0 : list2.size();
            int size2 = list3 == null ? 0 : list3.size();
            int size3 = list != null ? list.size() : 0;
            if (size + size2 != size3) {
                ((List) map3.get(modelType)).clear();
                netException = new NetException(android.support.v4.media.session.a.r(android.support.v4.media.session.a.w("Number of request models (", size3, ") != response models (valid: ", ", invalid: ", size), size2, ")"));
                timber.log.c.a(netException);
            }
        }
        final int i = 1;
        Map map5 = (Map) new io.reactivex.rxjava3.internal.operators.completable.m(c4893l.l(new com.quizlet.infra.legacysyncengine.models.serializers.a(11)), new HashMap(), new io.reactivex.rxjava3.functions.b() { // from class: com.quizlet.infra.legacysyncengine.tasks.parse.a
            @Override // io.reactivex.rxjava3.functions.b
            public final Object apply(Object obj, Object obj2) {
                Map map6 = (Map) obj;
                e eVar = (e) obj2;
                switch (i) {
                    case 0:
                        fVar.getClass();
                        map6.put(eVar.d, f.b(list, eVar));
                        break;
                    default:
                        fVar.getClass();
                        map6.put(eVar.e, f.b(list, eVar));
                        break;
                }
                return map6;
            }
        }).b();
        final int i2 = 0;
        return new com.quizlet.infra.legacysyncengine.tasks.parse.h(map3, map4, new com.quizlet.infra.legacysyncengine.net.request.i(netException, map5, (Map) new io.reactivex.rxjava3.internal.operators.completable.m(c4893l.l(new com.quizlet.infra.legacysyncengine.models.serializers.a(9)), new HashMap(), new io.reactivex.rxjava3.functions.b() { // from class: com.quizlet.infra.legacysyncengine.tasks.parse.a
            @Override // io.reactivex.rxjava3.functions.b
            public final Object apply(Object obj, Object obj2) {
                Map map6 = (Map) obj;
                e eVar = (e) obj2;
                switch (i2) {
                    case 0:
                        fVar.getClass();
                        map6.put(eVar.d, f.b(list, eVar));
                        break;
                    default:
                        fVar.getClass();
                        map6.put(eVar.e, f.b(list, eVar));
                        break;
                }
                return map6;
            }
        }).b()), com.quizlet.infra.legacysyncengine.tasks.parse.f.a(apiThreeWrapper));
    }

    @Override // androidx.camera.core.impl.utils.futures.a, com.google.android.datatransport.runtime.scheduling.persistence.e, io.reactivex.rxjava3.functions.h
    public com.google.common.util.concurrent.e apply(Object obj) throws CameraAccessException {
        k0 k0Var = (k0) this.a;
        CameraDevice cameraDevice = (CameraDevice) this.d;
        androidx.camera.camera2.internal.compat.params.q qVar = (androidx.camera.camera2.internal.compat.params.q) this.b;
        List list = (List) this.c;
        if (k0Var.v.b) {
            Iterator it2 = k0Var.b.n().iterator();
            while (it2.hasNext()) {
                ((k0) it2.next()).j();
            }
        }
        k0.l();
        synchronized (k0Var.a) {
            try {
                if (k0Var.m) {
                    return new androidx.camera.core.impl.utils.futures.k(new CancellationException("Opener is disabled"), 1);
                }
                c0 c0Var = k0Var.b;
                synchronized (c0Var.c) {
                    ((LinkedHashSet) c0Var.f).add(k0Var);
                }
                androidx.concurrent.futures.l lVarB = Y5.b(new j0(k0Var, list, new com.airbnb.lottie.network.d(cameraDevice, k0Var.c), qVar));
                k0Var.h = lVarB;
                androidx.appcompat.app.L l = new androidx.appcompat.app.L(k0Var, 2);
                lVarB.a(new androidx.camera.core.impl.utils.futures.h(0, lVarB, l), com.google.android.gms.internal.mlkit_vision_barcode.T.a());
                return androidx.camera.core.impl.utils.futures.i.d(k0Var.h);
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    @Override // com.quizlet.uicommon.ui.common.dialogs.f
    public void c(com.quizlet.uicommon.ui.common.dialogs.e eVar, int i) {
        int i2 = 1;
        int i3 = 0;
        String string = eVar.f(0).getText().toString();
        com.quizlet.features.setpage.utils.setpermissions.f fVar = (com.quizlet.features.setpage.utils.setpermissions.f) this.a;
        fVar.getClass();
        com.quizlet.baseui.base.b bVar = (com.quizlet.baseui.base.b) this.c;
        bVar.I(true);
        DBEnteredSetPassword dBEnteredSetPassword = new DBEnteredSetPassword();
        dBEnteredSetPassword.setSetId(((DBStudySet) this.d).getId());
        dBEnteredSetPassword.setPersonId(fVar.a.getPersonId());
        dBEnteredSetPassword.setPassword(string);
        ArrayList arrayList = new ArrayList();
        arrayList.add(dBEnteredSetPassword);
        HashMap map = new HashMap();
        map.put("data", arrayList);
        try {
            String strWriteValueAsString = fVar.b.writeValueAsString(map);
            Pattern pattern = okhttp3.w.e;
            new io.reactivex.rxjava3.internal.operators.single.e(new io.reactivex.rxjava3.internal.operators.single.d(fVar.e.u(C1412o.g(AbstractC3347h2.c("application/json"), strWriteValueAsString)), new com.quizlet.analytics.marketing.e(bVar, 11), i2), new com.quizlet.eventlogger.e(bVar, 9), i3).l(fVar.f).h(fVar.g).i(new com.quizlet.features.setpage.utils.setpermissions.e(fVar, bVar, (com.appsflyer.a) this.b, i3), new com.quizlet.billing.manager.b(5, fVar, bVar));
        } catch (JsonProcessingException e) {
            bVar.I(false);
            timber.log.c.a.e(e);
        }
        eVar.dismiss();
    }

    @Override // androidx.concurrent.futures.j
    public Object d(androidx.concurrent.futures.i iVar) {
        String str;
        k0 k0Var = (k0) this.a;
        List list = (List) this.c;
        com.airbnb.lottie.network.d dVar = (com.airbnb.lottie.network.d) this.d;
        androidx.camera.camera2.internal.compat.params.q qVar = (androidx.camera.camera2.internal.compat.params.q) this.b;
        synchronized (k0Var.a) {
            synchronized (k0Var.a) {
                synchronized (k0Var.a) {
                    try {
                        List list2 = k0Var.k;
                        if (list2 != null) {
                            Iterator it2 = list2.iterator();
                            while (it2.hasNext()) {
                                ((androidx.camera.core.impl.J) it2.next()).b();
                            }
                            k0Var.k = null;
                        }
                    } finally {
                    }
                }
                if (!list.isEmpty()) {
                    int i = 0;
                    do {
                        try {
                            ((androidx.camera.core.impl.J) list.get(i)).d();
                            i++;
                        } catch (DeferrableSurface$SurfaceClosedException e) {
                            for (int i2 = i - 1; i2 >= 0; i2--) {
                                ((androidx.camera.core.impl.J) list.get(i2)).b();
                            }
                            throw e;
                        }
                    } while (i < list.size());
                }
                k0Var.k = list;
            }
            AbstractC3242q6.h("The openCaptureSessionCompleter can only set once!", k0Var.i == null);
            k0Var.i = iVar;
            ((androidx.camera.camera2.internal.compat.m) dVar.b).v(qVar);
            str = "openCaptureSession[session=" + k0Var + "]";
        }
        return str;
    }

    @Override // com.google.android.gms.tasks.c
    public void t(Exception exc) {
        CredentialProviderPlayServicesImpl.onClearCredential$lambda$4((CredentialProviderPlayServicesImpl) this.a, (CancellationSignal) this.c, (Executor) this.d, (androidx.credentials.e) this.b, exc);
    }

    public /* synthetic */ j0(Object obj, Object obj2, Object obj3, Object obj4) {
        this.a = obj;
        this.c = obj2;
        this.d = obj3;
        this.b = obj4;
    }
}
