package com.google.firebase.tracing;

import android.content.Intent;
import android.content.res.Resources;
import android.graphics.drawable.Drawable;
import android.media.MediaPlayer;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.Trace;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.camera.camera2.internal.c0;
import androidx.compose.ui.node.V;
import androidx.coordinatorlayout.widget.CoordinatorLayout;
import androidx.core.view.D0;
import androidx.core.view.InterfaceC1062t;
import androidx.fragment.app.AbstractC1136h0;
import androidx.fragment.app.C1126c0;
import androidx.fragment.app.m0;
import androidx.work.impl.A;
import com.amazon.device.ads.DTBAdRequest;
import com.amazon.device.ads.DTBAdSize;
import com.appsflyer.deeplink.DeepLink;
import com.appsflyer.deeplink.DeepLinkListener;
import com.appsflyer.deeplink.DeepLinkResult;
import com.bumptech.glide.Glide;
import com.comscore.streaming.EventType;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import com.google.android.gms.ads.admanager.AdManagerAdRequest;
import com.google.android.gms.ads.admanager.AdManagerAdView;
import com.google.android.gms.common.api.internal.k;
import com.google.android.gms.internal.mlkit_vision_barcode.C7;
import com.google.android.gms.internal.mlkit_vision_document_scanner.E4;
import com.google.android.gms.tasks.OnCompleteListener;
import com.google.android.gms.tasks.Task;
import com.google.android.gms.tasks.m;
import com.google.firebase.components.d;
import com.j256.ormlite.dao.Dao;
import com.onetrust.otpublishers.headless.Internal.Log.OTLogger;
import com.onetrust.otpublishers.headless.Public.OTNetworkRequestCallback;
import com.quizlet.api.model.ApiResponse;
import com.quizlet.background.eventlogging.EventLogSyncingWorker;
import com.quizlet.data.model.C4151n1;
import com.quizlet.data.model.k2;
import com.quizlet.data.repository.classfolder.e;
import com.quizlet.db.data.database.DatabaseHelper;
import com.quizlet.db.data.models.base.DBModel;
import com.quizlet.db.data.models.identity.ModelIdentityCollection;
import com.quizlet.db.data.models.persisted.DBStudySet;
import com.quizlet.db.data.models.persisted.DBTerm;
import com.quizlet.db.data.models.persisted.base.ModelType;
import com.quizlet.db.data.models.persisted.base.Models;
import com.quizlet.db.data.models.persisted.fields.DBStudySetFields;
import com.quizlet.db.data.models.persisted.fields.DBTermFields;
import com.quizlet.db.data.net.tasks.ExecutionRouter;
import com.quizlet.eventlogger.LogRollCompletionListener;
import com.quizlet.features.achievements.achievement.AchievementEarnedView;
import com.quizlet.generated.enums.EnumC4530x;
import com.quizlet.infra.legacysyncengine.datasources.q;
import com.quizlet.infra.legacysyncengine.datasources.w;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.t;
import com.quizlet.quizletandroid.ui.common.ads.H;
import com.quizlet.quizletandroid.ui.common.ads.I;
import com.quizlet.quizletandroid.ui.common.ads.prebid.g;
import com.quizlet.quizletandroid.ui.joincontenttofolder.SelectableFolderListFragment;
import com.quizlet.quizletandroid.ui.qrcodes.QLiveQrCodeReaderActivity;
import com.quizlet.quizletandroid.ui.studymodes.write.WriteModeActivity;
import com.quizlet.qutils.rx.b;
import io.reactivex.rxjava3.core.c;
import io.reactivex.rxjava3.core.i;
import io.reactivex.rxjava3.core.j;
import io.reactivex.rxjava3.core.r;
import io.reactivex.rxjava3.functions.h;
import io.reactivex.rxjava3.internal.operators.maybe.f;
import io.reactivex.rxjava3.internal.operators.observable.C4899s;
import io.reactivex.rxjava3.internal.operators.observable.E;
import io.reactivex.rxjava3.internal.operators.observable.U;
import io.reactivex.rxjava3.subjects.p;
import io.reactivex.rxjava3.subjects.s;
import java.io.File;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import kotlin.Unit;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.F;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;
import okhttp3.z;
import org.json.JSONException;
import retrofit2.C5177b;

/* loaded from: classes2.dex */
public final /* synthetic */ class a implements d, OTNetworkRequestCallback, r, DeepLinkListener, LogRollCompletionListener, h, InterfaceC1062t, j, c, com.pubmatic.sdk.openwrap.eventhandler.dfp.a, m0, OnCompleteListener, b {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;
    public final /* synthetic */ Object c;

    public /* synthetic */ a(int i, Object obj, Object obj2) {
        this.a = i;
        this.b = obj;
        this.c = obj2;
    }

    @Override // com.quizlet.eventlogger.LogRollCompletionListener
    public void a(boolean z) {
        if (z) {
            ((EventLogSyncingWorker) this.b).f.d(new com.quizlet.background.eventlogging.a(0));
        }
        ((CountDownLatch) this.c).countDown();
    }

    @Override // io.reactivex.rxjava3.functions.h
    public Object apply(Object obj) {
        com.quizlet.data.model.billing.a aVar;
        i iVarM;
        switch (this.a) {
            case 5:
                com.quizlet.billing.subscriptions.h hVar = (com.quizlet.billing.subscriptions.h) this.c;
                hVar.getClass();
                if (!((Boolean) obj).booleanValue()) {
                    return f.a;
                }
                com.quizlet.billing.manager.f fVar = hVar.i;
                fVar.getClass();
                String sku = (String) this.b;
                Intrinsics.checkNotNullParameter(sku, "sku");
                io.reactivex.rxjava3.subjects.r rVar = fVar.g;
                com.google.android.gms.ads.internal.util.client.d dVar = new com.google.android.gms.ads.internal.util.client.d(sku);
                rVar.getClass();
                io.reactivex.rxjava3.internal.operators.maybe.h hVar2 = new io.reactivex.rxjava3.internal.operators.maybe.h(3, rVar, dVar);
                Intrinsics.checkNotNullExpressionValue(hVar2, "flatMapMaybe(...)");
                return hVar2;
            case 6:
                com.quizlet.billing.model.a inventory = (com.quizlet.billing.model.a) obj;
                com.google.android.material.floatingactionbutton.c cVar = ((com.quizlet.billing.subscriptions.h) this.b).h;
                com.quizlet.billing.subscriptions.j subscriptionPackage = (com.quizlet.billing.subscriptions.j) this.c;
                Intrinsics.checkNotNullParameter(subscriptionPackage, "subscriptionPackage");
                Intrinsics.checkNotNullParameter(inventory, "inventory");
                String sku2 = ((com.quizlet.billing.manager.sku.a) cVar.b).a(subscriptionPackage);
                Intrinsics.checkNotNullParameter(sku2, "sku");
                if (inventory != null) {
                    Intrinsics.checkNotNullParameter(sku2, "sku");
                    aVar = (com.quizlet.data.model.billing.a) inventory.a.get(sku2);
                } else {
                    aVar = null;
                }
                return com.google.android.gms.common.wrappers.a.d(aVar);
            case 7:
                Throwable e = (Throwable) obj;
                Intrinsics.checkNotNullParameter(e, "e");
                ((org.slf4j.b) ((e) this.b).d).j("Network error trying to save ClassFolders", e);
                return (List) this.c;
            case 15:
                List<com.quizlet.infra.legacysyncengine.net.request.c> list = (List) obj;
                com.quizlet.infra.legacysyncengine.net.f fVar2 = (com.quizlet.infra.legacysyncengine.net.f) this.b;
                HashSet hashSet = fVar2.g;
                ModelType modelType = (ModelType) this.c;
                hashSet.remove(modelType);
                com.jakewharton.rxbinding4.a aVarO = i.o(list);
                HashSet hashSet2 = new HashSet();
                for (com.quizlet.infra.legacysyncengine.net.request.c cVar2 : list) {
                    cVar2.getClass();
                    HashMap map = new HashMap();
                    Iterator it2 = cVar2.a.iterator();
                    while (it2.hasNext()) {
                        for (Map.Entry entry : ((com.quizlet.infra.legacysyncengine.net.request.h) it2.next()).a.entrySet()) {
                            if (!map.containsKey(entry.getKey())) {
                                map.put((ModelType) entry.getKey(), new HashSet());
                            }
                            ((Set) map.get(entry.getKey())).addAll((Collection) entry.getValue());
                        }
                    }
                    Set set = (Set) map.get(modelType);
                    if (set != null) {
                        hashSet2.addAll(set);
                    }
                }
                if (hashSet2.size() > 0) {
                    HashSet hashSet3 = new HashSet();
                    hashSet3.add(i.o(fVar2.a.getToManyRelationships(modelType)).l(new com.quizlet.infra.legacysyncengine.models.serializers.a(2)).m(new com.quizlet.infra.legacysyncengine.net.d(fVar2, 1), SubsamplingScaleImageView.TILE_SIZE_AUTO));
                    hashSet3.add(i.o(fVar2.f).l(new com.quizlet.infra.legacysyncengine.net.e(modelType)).m(new a(16, fVar2, hashSet2), SubsamplingScaleImageView.TILE_SIZE_AUTO));
                    iVarM = i.o(hashSet3).m(new com.quizlet.infra.legacysyncengine.models.serializers.a(1), SubsamplingScaleImageView.TILE_SIZE_AUTO);
                } else {
                    iVarM = E.a;
                }
                HashMap map2 = fVar2.h;
                if (map2.containsKey(modelType)) {
                    fVar2.c(modelType).c(new com.quizlet.infra.legacysyncengine.utils.b((s) map2.remove(modelType), 0));
                }
                return i.r(aVarO, iVarM);
            case 16:
                final com.quizlet.quizletandroid.data.net.synchooks.a aVar2 = (com.quizlet.quizletandroid.data.net.synchooks.a) obj;
                final com.quizlet.infra.legacysyncengine.net.f fVar3 = (com.quizlet.infra.legacysyncengine.net.f) this.b;
                fVar3.getClass();
                final HashSet hashSet4 = (HashSet) this.c;
                switch (aVar2.a) {
                    case 0:
                        return new com.jakewharton.rxbinding4.a(new com.quizlet.data.repository.activitycenter.a(aVar2, 5), 4);
                    default:
                        final p pVarZ = p.z();
                        ((ExecutionRouter) aVar2.c).f(new Callable() { // from class: com.quizlet.quizletandroid.data.net.synchooks.b
                            @Override // java.util.concurrent.Callable
                            public final Object call() {
                                a aVar3 = aVar2;
                                aVar3.getClass();
                                ModelIdentityCollection modelIdentityCollection = new ModelIdentityCollection(hashSet4);
                                DatabaseHelper databaseHelper = aVar3.b;
                                Collection collectionValues = databaseHelper.p(modelIdentityCollection, false).values();
                                HashSet hashSet5 = new HashSet();
                                Iterator it3 = collectionValues.iterator();
                                while (it3.hasNext()) {
                                    hashSet5.add(Long.valueOf(((DBTerm) ((DBModel) it3.next())).getSetId()));
                                }
                                Iterator it4 = databaseHelper.r(Models.TERM, false).in(DBTermFields.SET.getDatabaseColumnName(), hashSet5).and().le(DBTermFields.ID.getDatabaseColumnName(), 0).query().iterator();
                                while (it4.hasNext()) {
                                    hashSet5.remove(Long.valueOf(((DBTerm) it4.next()).getSetId()));
                                }
                                ArrayList arrayList = new ArrayList();
                                for (DBStudySet dBStudySet : databaseHelper.r(Models.STUDY_SET, false).in(DBStudySetFields.ID.getDatabaseColumnName(), hashSet5).query()) {
                                    if (dBStudySet.getPublishedTimestamp() <= 0) {
                                        dBStudySet.setNumTerms((int) databaseHelper.r(Models.TERM, false).eq(DBTermFields.SET.getDatabaseColumnName(), Long.valueOf(dBStudySet.getId())).countOf());
                                        dBStudySet.setPublishedTimestamp(Long.valueOf(System.currentTimeMillis() / 1000));
                                        arrayList.add(dBStudySet);
                                    }
                                }
                                int size = arrayList.size();
                                p pVar = pVarZ;
                                if (size > 0) {
                                    fVar3.b(arrayList).c(new com.quizlet.infra.legacysyncengine.utils.b(pVar, 0));
                                    return null;
                                }
                                pVar.onComplete();
                                return null;
                            }
                        });
                        return pVarZ;
                }
            case 17:
                e eVar = (e) this.b;
                eVar.getClass();
                return eVar.o((Integer) obj, ((com.quizlet.infra.legacysyncengine.net.request.h) this.c).c.getPagingToken());
            case 18:
                List list2 = (List) obj;
                k kVar = (k) this.b;
                com.quizlet.infra.legacysyncengine.net.constants.a aVar3 = (com.quizlet.infra.legacysyncengine.net.constants.a) ((U) this.c).a;
                V v = (V) kVar.d;
                com.google.android.datatransport.cct.internal.s sVar = (com.google.android.datatransport.cct.internal.s) v.f;
                com.quizlet.infra.legacysyncengine.net.request.j jVar = new com.quizlet.infra.legacysyncengine.net.request.j(list2, aVar3, (ExecutionRouter) v.c, (androidx.work.impl.model.c) v.d, (com.quizlet.infra.legacysyncengine.tasks.parse.f) v.e, sVar, (com.squareup.otto.c) v.g, (DatabaseHelper) v.h);
                return new io.reactivex.rxjava3.internal.operators.flowable.b(new com.quizlet.data.repository.activitycenter.a(jVar, 3), 4).e(new com.quizlet.infra.legacysyncengine.net.request.a(jVar, 0)).g(new com.quizlet.infra.legacysyncengine.net.request.a(jVar, 1)).m();
            default:
                return new com.quizlet.infra.legacysyncengine.tasks.parse.e((ModelType) obj, ((ApiResponse) this.b).getError().getModelWrapper(), ((Integer) ((androidx.core.util.c) this.c).b).intValue());
        }
    }

    public void b() {
        ((AdManagerAdView) ((g) this.b).f.getValue()).loadAd((AdManagerAdRequest) this.c);
    }

    public void c(io.reactivex.rxjava3.internal.operators.maybe.d emitter) {
        switch (this.a) {
            case 8:
                Intrinsics.checkNotNullParameter(emitter, "emitter");
                com.quizlet.data.model.U u = (com.quizlet.data.model.U) ((LinkedHashMap) ((com.quizlet.data.repository.explanations.exercise.b) this.c).d).get((String) this.b);
                if (u != null) {
                    emitter.b(u);
                }
                emitter.onComplete();
                break;
            case 9:
                Intrinsics.checkNotNullParameter(emitter, "emitter");
                C4151n1 c4151n1 = (C4151n1) ((LinkedHashMap) ((com.quizlet.data.repository.explanations.question.a) this.c).d).get((String) this.b);
                if (c4151n1 != null) {
                    emitter.b(c4151n1);
                }
                emitter.onComplete();
                break;
            default:
                Intrinsics.checkNotNullParameter(emitter, "emitter");
                k2 k2Var = (k2) ((LinkedHashMap) ((com.quizlet.data.repository.explanations.textbook.a) this.c).d).get((String) this.b);
                if (k2Var != null) {
                    emitter.b(k2Var);
                }
                emitter.onComplete();
                break;
        }
    }

    @Override // com.pubmatic.sdk.openwrap.eventhandler.dfp.a
    public void configure(AdManagerAdView adManagerAdView, AdManagerAdRequest.Builder builder, com.pubmatic.sdk.openwrap.core.f fVar) {
        Intrinsics.checkNotNullParameter(adManagerAdView, "<unused var>");
        Intrinsics.checkNotNullParameter(builder, "builder");
        ((I) this.b).getClass();
        H h = (H) this.c;
        String str = h.d.b;
        if (str != null && !StringsKt.O(str)) {
            builder.setContentUrl(coil3.network.g.b(str));
        }
        for (Map.Entry entry : h.e.entrySet()) {
            builder.addCustomTargeting((String) entry.getKey(), (String) entry.getValue());
        }
        for (Map.Entry entry2 : h.f.entrySet()) {
            builder.addCustomTargeting((String) entry2.getKey(), (String) entry2.getValue());
        }
        for (Map.Entry entry3 : ((Map) h.g.invoke()).entrySet()) {
            builder.addCustomTargeting((String) entry3.getKey(), (List<String>) entry3.getValue());
        }
    }

    @Override // io.reactivex.rxjava3.core.c
    public void e(final io.reactivex.rxjava3.internal.operators.completable.d emitter) throws IllegalStateException {
        Intrinsics.checkNotNullParameter(emitter, "emitter");
        final com.quizlet.quizletandroid.audio.players.h hVar = (com.quizlet.quizletandroid.audio.players.h) this.b;
        hVar.c = emitter;
        io.reactivex.rxjava3.internal.disposables.a.d(emitter, new io.reactivex.rxjava3.disposables.d(new com.quizlet.infra.legacysyncengine.net.okhttp.a(hVar, 1), 1));
        final MediaPlayer mediaPlayer = (MediaPlayer) this.c;
        mediaPlayer.setOnPreparedListener(new MediaPlayer.OnPreparedListener() { // from class: com.quizlet.quizletandroid.audio.players.d
            @Override // android.media.MediaPlayer.OnPreparedListener
            public final void onPrepared(MediaPlayer mediaPlayer2) throws IllegalStateException {
                MediaPlayer mediaPlayer3 = mediaPlayer;
                timber.log.c.a.g("MediaPlayer prepared, starting playback", new Object[0]);
                try {
                    mediaPlayer3.start();
                } catch (IllegalStateException e) {
                    com.google.android.exoplayer2.drm.b.m(emitter, e);
                }
            }
        });
        mediaPlayer.setOnErrorListener(new MediaPlayer.OnErrorListener() { // from class: com.quizlet.quizletandroid.audio.players.e
            @Override // android.media.MediaPlayer.OnErrorListener
            public final boolean onError(MediaPlayer mediaPlayer2, int i, int i2) {
                h hVar2 = hVar;
                hVar2.getClass();
                String strD = AbstractC0147y.d("MediaPlayer error occurred: ", i != -1010 ? i != -1007 ? i != -1004 ? i != -110 ? i != 100 ? i != 200 ? AbstractC0147y.c(i, "Unspecified media error (Code ", ")") : "Media is not valid for progressive playback" : "Media server died" : "An operation took too long to complete" : "File or network related operation errors" : "Bitstream is not conforming to the related coding standard or file spec" : "Media framework does not support the feature");
                timber.log.a aVar = timber.log.c.a;
                aVar.d(strD, new Object[0]);
                io.reactivex.rxjava3.internal.operators.completable.d dVar = emitter;
                if (i == 100) {
                    aVar.g("Attempting to re-initialize MediaPlayer", new Object[0]);
                    hVar2.b();
                    aVar.g("Initializing new MediaPlayer instance...", new Object[0]);
                    hVar2.b = new MediaPlayer();
                    dVar.onComplete();
                } else {
                    if (i == -1010 || i == -1007) {
                        File file = hVar2.a;
                        if (file != null && file.exists()) {
                            file.delete();
                        }
                        File file2 = hVar2.a;
                        aVar.g(android.support.v4.media.session.a.B("Deleted file ", file2 != null ? file2.getPath() : null, " due to unsupported/malformed media"), new Object[0]);
                    }
                    com.google.android.exoplayer2.drm.b.m(dVar, new IllegalStateException(strD));
                }
                hVar2.a = null;
                hVar2.c = null;
                hVar2.a();
                return true;
            }
        });
        mediaPlayer.setOnCompletionListener(new MediaPlayer.OnCompletionListener() { // from class: com.quizlet.quizletandroid.audio.players.f
            @Override // android.media.MediaPlayer.OnCompletionListener
            public final void onCompletion(MediaPlayer mediaPlayer2) {
                timber.log.a aVar = timber.log.c.a;
                h hVar2 = hVar;
                File file = hVar2.a;
                aVar.g(AbstractC0147y.d("MediaPlayer completed playback of file ", file != null ? file.getPath() : null), new Object[0]);
                hVar2.a = null;
                hVar2.c = null;
                hVar2.a();
                emitter.onComplete();
            }
        });
        mediaPlayer.setAudioStreamType(3);
        mediaPlayer.setVolume(1.0f, 1.0f);
        hVar.d.b(Unit.a);
        try {
            timber.log.c.a.g("Preparing MediaPlayer", new Object[0]);
            mediaPlayer.prepareAsync();
        } catch (IllegalStateException e) {
            com.google.android.exoplayer2.drm.b.m(emitter, e);
        }
    }

    @Override // com.google.firebase.components.d
    public Object f(c0 c0Var) {
        String str = (String) this.b;
        com.google.firebase.components.a aVar = (com.google.firebase.components.a) this.c;
        try {
            Trace.beginSection(str);
            return aVar.f.f(c0Var);
        } finally {
            Trace.endSection();
        }
    }

    @Override // io.reactivex.rxjava3.core.r
    public void j(io.reactivex.rxjava3.internal.operators.single.c it2) throws JSONException, IllegalArgumentException {
        Object next;
        Object obj = this.c;
        Object obj2 = this.b;
        switch (this.a) {
            case 2:
                Intrinsics.checkNotNullParameter(it2, "it");
                DTBAdRequest dTBAdRequest = (DTBAdRequest) ((t) ((com.google.mlkit.vision.documentscanner.internal.c) obj2).b).get();
                com.google.mlkit.common.sdkinternal.model.a aVar = com.quizlet.ads.c.b;
                com.quizlet.ads.c cVar = (com.quizlet.ads.c) obj;
                if (!cVar.a(false).isEmpty()) {
                    Iterator it3 = cVar.a(false).iterator();
                    String str = null;
                    if (it3.hasNext()) {
                        next = it3.next();
                        if (it3.hasNext()) {
                            com.google.android.gms.ads.h hVar = (com.google.android.gms.ads.h) next;
                            int i = hVar.a * hVar.b;
                            do {
                                Object next2 = it3.next();
                                com.google.android.gms.ads.h hVar2 = (com.google.android.gms.ads.h) next2;
                                int i2 = hVar2.a * hVar2.b;
                                if (i < i2) {
                                    next = next2;
                                    i = i2;
                                }
                            } while (it3.hasNext());
                        }
                    } else {
                        next = null;
                    }
                    com.google.android.gms.ads.h INVALID = (com.google.android.gms.ads.h) next;
                    if (INVALID == null) {
                        INVALID = com.google.android.gms.ads.h.q;
                        Intrinsics.checkNotNullExpressionValue(INVALID, "INVALID");
                    }
                    if (Intrinsics.b(INVALID, com.google.android.gms.ads.h.i)) {
                        str = "09196de0-2c94-42b9-b7c4-70eedc3da453";
                    } else if (Intrinsics.b(INVALID, com.google.android.gms.ads.h.l)) {
                        str = "c29dbf9a-5440-4fde-b2e5-9519be13bdb4";
                    } else if (Intrinsics.b(INVALID, com.google.android.gms.ads.h.m)) {
                        str = "31a4fe65-b235-461c-9644-ccde94d987af";
                    }
                    if (str != null) {
                        dTBAdRequest.setSizes(new DTBAdSize(INVALID.a, INVALID.b, str));
                        dTBAdRequest.loadAd(new com.quizlet.ads.a(it2));
                        break;
                    } else {
                        it2.onSuccess(kotlin.collections.V.c());
                        break;
                    }
                } else {
                    it2.onSuccess(kotlin.collections.V.c());
                    break;
                }
            default:
                Dao dao = (Dao) obj2;
                List list = (List) obj;
                Intrinsics.checkNotNullParameter(it2, "emitter");
                try {
                    it2.onSuccess((List) dao.callBatchTasks(new A(9, list, dao)));
                    break;
                } catch (Throwable th) {
                    timber.log.c.a.g("Database Query for Models:\n" + list, new Object[0]);
                    if (it2.b(th)) {
                        return;
                    }
                    C7.c(th);
                }
        }
    }

    @Override // io.reactivex.rxjava3.core.j
    public void l(C4899s emitter) {
        switch (this.a) {
            case 12:
                Intrinsics.checkNotNullParameter(emitter, "emitter");
                q qVar = new q(emitter, 0);
                com.quizlet.infra.legacysyncengine.datasources.p pVar = (com.quizlet.infra.legacysyncengine.datasources.p) this.b;
                com.quizlet.infra.legacysyncengine.net.c cVar = pVar.c;
                com.quizlet.infra.legacysyncengine.orm.query.a aVar = (com.quizlet.infra.legacysyncengine.orm.query.a) this.c;
                cVar.e(aVar, qVar);
                io.reactivex.rxjava3.internal.disposables.a.d(emitter, new com.quizlet.infra.legacysyncengine.datasources.s(pVar, aVar, qVar, 0));
                break;
            case 13:
                Intrinsics.checkNotNullParameter(emitter, "emitter");
                q qVar2 = new q(emitter, 1);
                com.quizlet.infra.legacysyncengine.datasources.p pVar2 = (com.quizlet.infra.legacysyncengine.datasources.p) this.b;
                com.quizlet.infra.legacysyncengine.net.c cVar2 = pVar2.c;
                com.quizlet.infra.legacysyncengine.orm.query.a aVar2 = (com.quizlet.infra.legacysyncengine.orm.query.a) this.c;
                cVar2.e(aVar2, qVar2);
                io.reactivex.rxjava3.internal.disposables.a.d(emitter, new com.quizlet.infra.legacysyncengine.datasources.s(pVar2, aVar2, qVar2, 1));
                break;
            default:
                w wVar = (w) this.b;
                wVar.getClass();
                q qVar3 = new q(emitter, 2);
                com.quizlet.infra.legacysyncengine.net.c cVar3 = wVar.b;
                com.quizlet.infra.legacysyncengine.orm.query.a aVar3 = (com.quizlet.infra.legacysyncengine.orm.query.a) this.c;
                cVar3.e(aVar3, qVar3);
                io.reactivex.rxjava3.internal.disposables.a.d(emitter, new com.quizlet.infra.legacysyncengine.datasources.s(wVar, aVar3, qVar3));
                break;
        }
    }

    @Override // com.google.android.gms.tasks.OnCompleteListener
    public void onComplete(Task it2) {
        Intrinsics.checkNotNullParameter(it2, "it");
        m mVar = (m) this.b;
        if (mVar.l()) {
            Object objH = mVar.h();
            Intrinsics.checkNotNullExpressionValue(objH, "getResult(...)");
            com.google.mlkit.vision.barcode.common.a aVar = (com.google.mlkit.vision.barcode.common.a) CollectionsKt.firstOrNull((List) objH);
            if (aVar != null) {
                String strE = aVar.a.e();
                com.google.android.datatransport.cct.internal.s sVar = (com.google.android.datatransport.cct.internal.s) this.c;
                com.google.firebase.crashlytics.internal.metadata.q qVar = (com.google.firebase.crashlytics.internal.metadata.q) sVar.i;
                if (qVar != null) {
                    ((Handler) sVar.g).removeCallbacks(qVar);
                }
                Uri uri = Uri.parse(strE == null ? "" : strE);
                if (Intrinsics.b(uri.getHost(), "quizlet.com")) {
                    List<String> pathSegments = uri.getPathSegments();
                    Intrinsics.checkNotNullExpressionValue(pathSegments, "getPathSegments(...)");
                    if (Intrinsics.b(CollectionsKt.firstOrNull(pathSegments), "live")) {
                        QLiveQrCodeReaderActivity qLiveQrCodeReaderActivity = (QLiveQrCodeReaderActivity) sVar.h;
                        if (qLiveQrCodeReaderActivity == null) {
                            Intrinsics.m("view");
                            throw null;
                        }
                        com.quizlet.live.a resultCode = com.quizlet.live.a.a;
                        Intrinsics.checkNotNullParameter(resultCode, "resultCode");
                        Intent intent = new Intent();
                        if (strE != null) {
                            intent.putExtra("url_scanned", strE);
                        }
                        qLiveQrCodeReaderActivity.setResult(1, intent);
                        qLiveQrCodeReaderActivity.finish();
                        return;
                    }
                }
                QLiveQrCodeReaderActivity qLiveQrCodeReaderActivity2 = (QLiveQrCodeReaderActivity) sVar.h;
                if (qLiveQrCodeReaderActivity2 != null) {
                    qLiveQrCodeReaderActivity2.d0();
                } else {
                    Intrinsics.m("view");
                    throw null;
                }
            }
        }
    }

    @Override // com.onetrust.otpublishers.headless.Public.OTNetworkRequestCallback
    public void onCompletion(boolean z) {
        if (z) {
            return;
        }
        com.onetrust.otpublishers.headless.Internal.Helper.a aVar = (com.onetrust.otpublishers.headless.Internal.Helper.a) this.c;
        OTLogger.c("GoogleVendorHelper", 3, "Google Vendor list Api called ");
        com.quizlet.data.repository.explanations.textbook.a aVar2 = new com.quizlet.data.repository.explanations.textbook.a(8);
        aVar2.c("https://geolocation.1trust.app/");
        aVar2.b(new C5177b(2));
        aVar2.a = new okhttp3.A(new z());
        ((com.onetrust.otpublishers.headless.Internal.Network.a) aVar2.e().b(com.onetrust.otpublishers.headless.Internal.Network.a.class)).a((String) this.b).j(new com.quizlet.data.repository.widget.b(13, aVar, null));
    }

    @Override // com.appsflyer.deeplink.DeepLinkListener
    public void onDeepLinking(DeepLinkResult it2) {
        Intrinsics.checkNotNullParameter(it2, "it");
        timber.log.c.a.a("AppsFlyer received deep link " + it2, new Object[0]);
        com.quizlet.analytics.marketing.appsflyer.b bVar = (com.quizlet.analytics.marketing.appsflyer.b) this.b;
        bVar.getClass();
        int i = com.quizlet.analytics.marketing.appsflyer.a.a[it2.getStatus().ordinal()];
        com.quizlet.analytics.marketing.b bVar2 = (com.quizlet.analytics.marketing.b) this.c;
        if (i != 1) {
            if (i == 2) {
                bVar2.b("AppsFlyer Deep link not found");
                return;
            }
            bVar2.b("AppsFlyer Deep link unknown error: " + it2.getError());
            return;
        }
        String deepLinkValue = it2.getDeepLink().getDeepLinkValue();
        DeepLink deepLink = it2.getDeepLink();
        Intrinsics.checkNotNullExpressionValue(deepLink, "getDeepLink(...)");
        String placement = deepLink.getStringValue("deep_link_sub1");
        if (placement != null) {
            com.quizlet.data.repository.folderwithcreatorinclass.e eVar = bVar.b;
            Intrinsics.checkNotNullParameter(placement, "placement");
            if (placement.equals(EnumC4530x.FIZZ_UPGRADE.a())) {
                kotlinx.coroutines.E.A((kotlinx.coroutines.internal.d) eVar.d, null, null, new com.quizlet.data.interactor.qincentives.c(eVar, null), 3);
            }
        }
        if (deepLinkValue != null) {
            bVar2.a(new com.quizlet.analytics.marketing.a(deepLinkValue));
        } else {
            bVar2.b("AppsFlyer Deep link is empty");
        }
    }

    @Override // com.quizlet.qutils.rx.b
    public void run() {
        WriteModeActivity writeModeActivity = (WriteModeActivity) this.b;
        String url = ((DBTerm) this.c).getDefinitionImageDefaultUrl(writeModeActivity.getResources().getDisplayMetrics().densityDpi);
        if (org.apache.commons.lang3.e.d(url)) {
            ((com.quizlet.quizletandroid.ui.common.images.loading.glide.a) writeModeActivity.m1).getClass();
            com.bumptech.glide.util.f.c(writeModeActivity, "You cannot start a load on a not yet attached View or a Fragment where getActivity() returns null (which usually occurs when getActivity() is called before the Fragment is attached or after the Fragment is destroyed).");
            com.bumptech.glide.m mRequestManager = Glide.a(writeModeActivity).e.c(writeModeActivity);
            Intrinsics.checkNotNullParameter(mRequestManager, "mRequestManager");
            Intrinsics.checkNotNullParameter(url, "url");
            com.quizlet.qutils.data.offline.c ttl = com.quizlet.qutils.data.offline.c.b;
            Intrinsics.checkNotNullParameter(url, "url");
            Intrinsics.checkNotNullParameter(ttl, "ttl");
            com.quizlet.quizletandroid.ui.common.images.loading.offline.a aVar = new com.quizlet.quizletandroid.ui.common.images.loading.offline.a(url);
            mRequestManager.getClass();
            com.bumptech.glide.k kVarD = new com.bumptech.glide.k(mRequestManager.a, mRequestManager, Drawable.class, mRequestManager.b).D(aVar);
            new com.bumptech.glide.util.c(0);
            kVarD.getClass();
            kVarD.A(new com.bumptech.glide.request.target.c(kVarD.r), kVarD);
        }
    }

    @Override // androidx.core.view.InterfaceC1062t
    public D0 w(D0 d0, View view) throws Resources.NotFoundException {
        androidx.core.graphics.e eVarG = d0.a.g(647);
        com.quizlet.features.setpage.r rVar = (com.quizlet.features.setpage.r) this.b;
        CoordinatorLayout snackbarLayoutWrapper = ((com.quizlet.features.setpage.databinding.a) rVar.K()).p;
        Intrinsics.checkNotNullExpressionValue(snackbarLayoutWrapper, "snackbarLayoutWrapper");
        snackbarLayoutWrapper.setPadding(snackbarLayoutWrapper.getPaddingLeft(), eVarG.b, snackbarLayoutWrapper.getPaddingRight(), snackbarLayoutWrapper.getPaddingBottom());
        Intrinsics.d(view);
        view.setPadding(eVarG.a, view.getPaddingTop(), eVarG.c, view.getPaddingBottom());
        FrameLayout termListFragmentContainer = ((com.quizlet.features.setpage.databinding.a) rVar.K()).q;
        Intrinsics.checkNotNullExpressionValue(termListFragmentContainer, "termListFragmentContainer");
        int dimensionPixelSize = rVar.getResources().getDimensionPixelSize(R.dimen.study_this_set_container_height);
        int i = eVarG.d;
        termListFragmentContainer.setPadding(termListFragmentContainer.getPaddingLeft(), termListFragmentContainer.getPaddingTop(), termListFragmentContainer.getPaddingRight(), dimensionPixelSize + i);
        int dimensionPixelSize2 = rVar.getResources().getDimensionPixelSize(R.dimen.ref_spacing_small);
        AchievementEarnedView achievementToast = ((com.quizlet.features.setpage.databinding.a) rVar.K()).b;
        Intrinsics.checkNotNullExpressionValue(achievementToast, "achievementToast");
        ViewGroup.LayoutParams layoutParams = achievementToast.getLayoutParams();
        if (layoutParams == null) {
            throw new NullPointerException("null cannot be cast to non-null type android.view.ViewGroup.MarginLayoutParams");
        }
        ViewGroup.MarginLayoutParams marginLayoutParams = (ViewGroup.MarginLayoutParams) layoutParams;
        marginLayoutParams.leftMargin = dimensionPixelSize2;
        marginLayoutParams.rightMargin = dimensionPixelSize2;
        marginLayoutParams.bottomMargin = dimensionPixelSize2 + i;
        achievementToast.setLayoutParams(marginLayoutParams);
        F f = (F) this.c;
        if (f.a) {
            ViewGroup viewGroupO = rVar.O();
            ViewGroup.LayoutParams layoutParams2 = viewGroupO.getLayoutParams();
            if (layoutParams2 == null) {
                throw new NullPointerException("null cannot be cast to non-null type android.view.ViewGroup.MarginLayoutParams");
            }
            ViewGroup.MarginLayoutParams marginLayoutParams2 = (ViewGroup.MarginLayoutParams) layoutParams2;
            marginLayoutParams2.bottomMargin = i;
            viewGroupO.setLayoutParams(marginLayoutParams2);
        }
        f.a = false;
        rVar.X = i;
        rVar.Y = rVar.getResources().getDimensionPixelSize(R.dimen.study_this_set_container_height) + i;
        return D0.b;
    }

    @Override // androidx.fragment.app.m0
    public void y(Bundle result, String requestKey) {
        Object obj = this.c;
        Object obj2 = this.b;
        switch (this.a) {
            case EventType.SUBS /* 25 */:
                Intrinsics.checkNotNullParameter(requestKey, "requestKey");
                Intrinsics.checkNotNullParameter(result, "result");
                if (requestKey.hashCode() == 450033372 && requestKey.equals("UpgradeFragmentRequestKey") && result.getInt("ResultUserUpgradeType", 0) != 0) {
                    E4.h((androidx.navigation.H) obj2, (Function1) obj);
                    break;
                }
                break;
            default:
                String str = SelectableFolderListFragment.v;
                Intrinsics.checkNotNullParameter(requestKey, "<unused var>");
                Intrinsics.checkNotNullParameter(result, "<unused var>");
                ((com.quizlet.quizletandroid.ui.globalnav.composable.s) obj2).invoke(Boolean.TRUE);
                C1126c0 c1126c0 = (C1126c0) ((AbstractC1136h0) obj).n.remove("createFolderRequestKey");
                if (c1126c0 != null) {
                    c1126c0.a.b(c1126c0.c);
                }
                AbstractC1136h0.N(2);
                break;
        }
    }

    public /* synthetic */ a(String str, int i, Object obj) {
        this.a = i;
        this.c = obj;
        this.b = str;
    }
}
