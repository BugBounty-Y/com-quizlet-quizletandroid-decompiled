package com.google.android.material.search;

import android.content.Intent;
import android.os.Bundle;
import android.util.Log;
import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.camera.camera2.internal.T;
import com.android.billingclient.api.Purchase;
import com.comscore.streaming.EventType;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import com.google.android.gms.internal.mlkit_vision_common.S3;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3665l4;
import com.google.android.gms.tasks.OnCompleteListener;
import com.google.android.gms.tasks.Task;
import com.google.firebase.crashlytics.internal.metadata.q;
import com.google.firebase.messaging.D;
import com.google.firebase.messaging.F;
import com.google.firebase.messaging.m;
import com.google.firebase.perf.network.FirebasePerfOkHttpClient;
import com.google.firebase.sessions.C3990l;
import com.google.firebase.sessions.O;
import com.google.firebase.sessions.P;
import com.onetrust.otpublishers.headless.Public.uiutils.OTVendorUtils;
import com.quizlet.api.model.PagingInfo;
import com.quizlet.data.model.C4135i0;
import com.quizlet.db.data.models.base.DBModel;
import com.quizlet.db.data.models.base.SortOption;
import com.quizlet.db.data.models.persisted.base.Models;
import com.quizlet.db.data.models.persisted.fields.DBStudySetFields;
import com.quizlet.features.folders.composables.J;
import com.quizlet.features.infra.legacyadapter.RecyclerViewFragment;
import com.quizlet.generated.enums.C1;
import com.quizlet.infra.legacysyncengine.datasources.p;
import com.quizlet.infra.legacysyncengine.datasources.w;
import com.quizlet.infra.legacysyncengine.models.serializers.ApiThreeRequestSerializer;
import io.reactivex.rxjava3.core.r;
import io.reactivex.rxjava3.internal.operators.observable.E;
import io.reactivex.rxjava3.internal.operators.observable.Z;
import java.io.File;
import java.io.IOException;
import java.text.Collator;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executor;
import java.util.concurrent.ScheduledFuture;
import java.util.stream.Collectors;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.Charsets;

/* loaded from: classes2.dex */
public final /* synthetic */ class a implements com.google.firebase.components.d, com.google.firebase.inject.a, com.google.android.gms.tasks.a, OnCompleteListener, com.google.android.gms.tasks.e, com.google.android.datatransport.e, OTVendorUtils.ItemListener, com.quizlet.qutils.rx.b, com.google.android.gms.tasks.d, androidx.swiperefreshlayout.widget.j, com.quizlet.uicommon.ui.common.dialogs.f, io.reactivex.rxjava3.functions.h, r {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;

    public /* synthetic */ a(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    public void a(com.android.billingclient.api.e it2) {
        Intrinsics.checkNotNullParameter(it2, "it");
        if (it2.a != 0) {
            timber.log.c.a.d(AbstractC0147y.d("Acknowledgement failed for purchase: ", ((Purchase) this.b).b()), new Object[0]);
        }
    }

    @Override // com.google.android.datatransport.e
    public Object apply(Object obj) {
        switch (this.a) {
            case 15:
                O o = (O) obj;
                ((C3990l) this.b).getClass();
                String strN = P.b.n(o);
                Intrinsics.checkNotNullExpressionValue(strN, "SessionEvents.SESSION_EVENT_ENCODER.encode(value)");
                o.getClass();
                byte[] bytes = strN.getBytes(Charsets.UTF_8);
                Intrinsics.checkNotNullExpressionValue(bytes, "getBytes(...)");
                return bytes;
            case EventType.VIDEO /* 24 */:
                p pVar = (p) this.b;
                pVar.getClass();
                com.quizlet.infra.legacysyncengine.orm.b bVar = new com.quizlet.infra.legacysyncengine.orm.b(Models.STUDY_SET);
                bVar.c(DBStudySetFields.ID, (HashSet) obj, null);
                bVar.e(DBStudySetFields.CREATOR);
                return pVar.c.c(bVar.a(), com.quizlet.infra.legacysyncengine.net.c.e);
            case EventType.SUBS /* 25 */:
                List list = (List) obj;
                if (((w) this.b).e != SortOption.ORIGINAL && list != null) {
                    Collator collator = Collator.getInstance();
                    collator.setStrength(0);
                    Collections.sort(list, new androidx.camera.core.internal.compat.workaround.a(collator, 2));
                }
                return list;
            case EventType.CDN /* 26 */:
                ((retrofit2.adapter.rxjava3.d) this.b).getClass();
                return retrofit2.adapter.rxjava3.d.t((C4135i0) obj);
            case 27:
                return ((ApiThreeRequestSerializer) this.b).requestFilesForModel((DBModel) obj);
            default:
                com.quizlet.infra.legacysyncengine.net.request.h hVar = (com.quizlet.infra.legacysyncengine.net.request.h) obj;
                com.quizlet.data.repository.classfolder.e eVar = (com.quizlet.data.repository.classfolder.e) this.b;
                eVar.getClass();
                Z zP = io.reactivex.rxjava3.core.i.p(hVar);
                io.reactivex.rxjava3.core.i iVarO = E.a;
                PagingInfo pagingInfo = hVar.c;
                if (pagingInfo != null) {
                    int total = (pagingInfo.getTotal() / 200) + (pagingInfo.getTotal() % 200 == 0 ? 0 : 1);
                    if (pagingInfo.getPage() < total) {
                        int page = pagingInfo.getPage() + 1;
                        if (page > total) {
                            throw new IllegalArgumentException("fromInclusive must be lower than toInclusive");
                        }
                        ArrayList arrayList = new ArrayList();
                        while (page <= total) {
                            arrayList.add(Integer.valueOf(page));
                            page++;
                        }
                        iVarO = io.reactivex.rxjava3.core.i.o(arrayList);
                    }
                }
                return io.reactivex.rxjava3.core.i.r(zP, iVarO.m(new com.google.firebase.tracing.a(17, eVar, hVar), SubsamplingScaleImageView.TILE_SIZE_AUTO));
        }
    }

    @Override // com.quizlet.uicommon.ui.common.dialogs.f
    public void c(com.quizlet.uicommon.ui.common.dialogs.e eVar, int i) {
        q qVar = (q) this.b;
        if (qVar != null) {
            qVar.run();
        }
        eVar.dismiss();
    }

    /* JADX WARN: Removed duplicated region for block: B:113:0x051c  */
    /* JADX WARN: Removed duplicated region for block: B:95:0x03d9  */
    /* JADX WARN: Removed duplicated region for block: B:97:0x03dc  */
    /* JADX WARN: Removed duplicated region for block: B:98:0x03e5  */
    @Override // com.google.firebase.components.d
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object f(androidx.camera.camera2.internal.c0 r49) throws android.content.res.Resources.NotFoundException, android.content.pm.PackageManager.NameNotFoundException {
        /*
            Method dump skipped, instructions count: 1482
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.material.search.a.f(androidx.camera.camera2.internal.c0):java.lang.Object");
    }

    @Override // com.google.android.gms.tasks.e
    public Task g(Object obj) {
        return S3.i((com.google.firebase.remoteconfig.internal.d) this.b);
    }

    @Override // com.google.android.gms.tasks.a
    public Object h(Task task) throws IOException {
        boolean z;
        switch (this.a) {
            case 6:
                ((com.onetrust.otpublishers.headless.UI.TVUI.datautils.d) this.b).getClass();
                if (task.l()) {
                    com.google.firebase.crashlytics.internal.common.a aVar = (com.google.firebase.crashlytics.internal.common.a) task.h();
                    String str = aVar.b;
                    Log.isLoggable("FirebaseCrashlytics", 3);
                    File file = aVar.c;
                    if (file.delete()) {
                        file.getPath();
                        Log.isLoggable("FirebaseCrashlytics", 3);
                    } else {
                        Log.w("FirebaseCrashlytics", "Crashlytics could not delete report file: " + file.getPath(), null);
                    }
                    z = true;
                } else {
                    Log.w("FirebaseCrashlytics", "Crashlytics report could not be enqueued to DataTransport", task.g());
                    z = false;
                }
                return Boolean.valueOf(z);
            case 7:
                ((CountDownLatch) this.b).countDown();
                return null;
            case 8:
                return (Task) ((com.google.firebase.crashlytics.internal.common.k) this.b).call();
            case 9:
                ((Runnable) this.b).run();
                return S3.i(null);
            default:
                ((m) this.b).getClass();
                Bundle bundle = (Bundle) task.i();
                if (bundle == null) {
                    throw new IOException("SERVICE_NOT_AVAILABLE");
                }
                String string = bundle.getString("registration_id");
                if (string != null || (string = bundle.getString("unregistered")) != null) {
                    return string;
                }
                String string2 = bundle.getString("error");
                if ("RST".equals(string2)) {
                    throw new IOException("INSTANCE_ID_RESET");
                }
                if (string2 != null) {
                    throw new IOException(string2);
                }
                Log.w("FirebaseMessaging", "Unexpected response: " + bundle, new Throwable());
                throw new IOException("SERVICE_NOT_AVAILABLE");
        }
    }

    @Override // com.google.firebase.inject.a
    public void i(com.google.firebase.inject.b bVar) {
        switch (this.a) {
            case 4:
                com.google.firebase.crashlytics.internal.a aVar = (com.google.firebase.crashlytics.internal.a) this.b;
                aVar.getClass();
                Log.isLoggable("FirebaseCrashlytics", 3);
                aVar.b.set((com.google.firebase.crashlytics.internal.a) bVar.get());
                break;
            default:
                com.quizlet.data.repository.explanations.question.a aVar2 = ((com.google.firebase.remoteconfig.f) ((com.google.firebase.remoteconfig.interop.a) bVar.get())).b("firebase").i;
                Set set = (Set) aVar2.d;
                com.google.firebase.crashlytics.internal.b bVar2 = (com.google.firebase.crashlytics.internal.b) this.b;
                set.add(bVar2);
                Task taskB = ((com.google.firebase.remoteconfig.internal.b) aVar2.a).b();
                taskB.d((Executor) aVar2.c, new T(aVar2, taskB, bVar2, 16));
                Log.isLoggable("FirebaseCrashlytics", 3);
                break;
        }
    }

    @Override // io.reactivex.rxjava3.core.r
    public void j(io.reactivex.rxjava3.internal.operators.single.c emitter) {
        Intrinsics.checkNotNullParameter(emitter, "emitter");
        okhttp3.internal.connection.g gVar = (okhttp3.internal.connection.g) this.b;
        io.reactivex.rxjava3.internal.disposables.a.d(emitter, new io.reactivex.rxjava3.disposables.d(new com.quizlet.infra.legacysyncengine.net.okhttp.a(gVar, 0), 1));
        FirebasePerfOkHttpClient.enqueue(gVar, new com.quizlet.ads.a(emitter));
    }

    @Override // com.google.android.gms.tasks.OnCompleteListener
    public void onComplete(Task task) {
        switch (this.a) {
            case 11:
                D.a((Intent) this.b);
                break;
            case 12:
                ((F) this.b).b.d(null);
                break;
            default:
                ((ScheduledFuture) this.b).cancel(false);
                break;
        }
    }

    @Override // com.onetrust.otpublishers.headless.Public.uiutils.OTVendorUtils.ItemListener
    public void onItemClick(String vendorMode, boolean z) {
        com.onetrust.otpublishers.headless.UI.viewmodel.e this$0 = (com.onetrust.otpublishers.headless.UI.viewmodel.e) this.b;
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        Intrinsics.checkNotNullParameter(vendorMode, "vendorMode");
        if (AbstractC3665l4.a(this$0.i).equals(vendorMode)) {
            this$0.j.l(Boolean.valueOf(z));
        }
    }

    @Override // androidx.swiperefreshlayout.widget.j
    public void onRefresh() {
        ((RecyclerViewFragment) this.b).r();
    }

    @Override // com.google.android.gms.tasks.d
    public void onSuccess(Object obj) {
        ((J) this.b).invoke(obj);
    }

    @Override // com.quizlet.qutils.rx.b
    public void run() {
        switch (this.a) {
            case 19:
                com.quizlet.features.infra.basestudy.manager.f fVar = (com.quizlet.features.infra.basestudy.manager.f) this.b;
                fVar.f.a(fVar.d).i(new com.quizlet.features.infra.basestudy.manager.e(fVar, 0), io.reactivex.rxjava3.internal.functions.d.e);
                break;
            default:
                com.quizlet.features.write.base.b bVar = (com.quizlet.features.write.base.b) this.b;
                com.quizlet.features.infra.basestudy.data.models.dataproviders.a aVar = bVar.u;
                if (aVar != null) {
                    List list = aVar.D;
                    new com.quizlet.features.infra.studysetting.managers.a(bVar.E, list == null ? Collections.EMPTY_LIST : (List) list.stream().filter(new com.fasterxml.jackson.databind.deser.std.a(2)).collect(Collectors.toList()), bVar.x.getPersonId(), bVar.u.f, C1.STANDARD);
                    break;
                } else {
                    timber.log.c.a.g("Study mode data provider not available, aborting data ready action", new Object[0]);
                    break;
                }
        }
    }
}
