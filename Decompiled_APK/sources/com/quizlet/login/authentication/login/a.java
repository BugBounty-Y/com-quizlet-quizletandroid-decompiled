package com.quizlet.login.authentication.login;

import android.media.MediaPlayer;
import android.view.View;
import androidx.camera.camera2.internal.AbstractC0147y;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import com.google.android.datatransport.cct.internal.s;
import com.google.android.gms.internal.mlkit_vision_barcode.U;
import com.google.android.gms.measurement.internal.J;
import com.quizlet.data.model.B0;
import com.quizlet.db.data.models.base.DBModel;
import com.quizlet.db.data.models.persisted.DBGroup;
import com.quizlet.db.data.models.persisted.DBUser;
import com.quizlet.db.data.models.persisted.base.Models;
import com.quizlet.db.data.models.persisted.fields.DBTermFields;
import com.quizlet.features.infra.legacyadapter.d;
import com.quizlet.generated.enums.w1;
import com.quizlet.infra.legacysyncengine.models.identity.QueryIdFieldChangeMapper;
import com.quizlet.offline.managers.i;
import com.quizlet.quizletandroid.ui.common.ads.InterfaceC4638e;
import com.quizlet.quizletandroid.ui.group.classuser.ClassUserListFragment;
import com.quizlet.quizletandroid.ui.profile.ProfileActivity;
import com.quizlet.quizletandroid.ui.profile.UserClassListFragment;
import com.quizlet.quizletandroid.ui.startpage.nav2.model.F;
import com.quizlet.remote.model.base.ApiThreeWrapper;
import com.quizlet.remote.service.InterfaceC4776c;
import com.quizlet.remote.service.m;
import io.reactivex.rxjava3.core.b;
import io.reactivex.rxjava3.core.p;
import io.reactivex.rxjava3.functions.h;
import io.reactivex.rxjava3.internal.operators.completable.c;
import io.reactivex.rxjava3.internal.operators.maybe.e;
import io.reactivex.rxjava3.internal.operators.maybe.j;
import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.SynchronousQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import kotlin.Pair;
import kotlin.Unit;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;
import okhttp3.A;
import okhttp3.C;
import okhttp3.internal.connection.g;
import retrofit2.K;

/* loaded from: classes3.dex */
public final class a implements h, InterfaceC4638e, d, b {
    public final /* synthetic */ int a;
    public Object b;

    public /* synthetic */ a(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    @Override // io.reactivex.rxjava3.core.b
    public void a(io.reactivex.rxjava3.disposables.b bVar) {
        ((b) this.b).a(bVar);
    }

    /* JADX WARN: Multi-variable type inference failed */
    @Override // io.reactivex.rxjava3.functions.h
    public Object apply(Object obj) {
        switch (this.a) {
            case 0:
                K it2 = (K) obj;
                Intrinsics.checkNotNullParameter(it2, "it");
                return io.ktor.client.plugins.api.d.g((io.ktor.client.plugins.api.d) this.b, null, it2);
            case 1:
                Pair pair = (Pair) obj;
                Intrinsics.checkNotNullParameter(pair, "<destruct>");
                Object obj2 = pair.a;
                Intrinsics.checkNotNullExpressionValue(obj2, "component1(...)");
                com.quizlet.qutils.data.offline.d payload = (com.quizlet.qutils.data.offline.d) pair.b;
                s sVar = ((i) this.b).f;
                long jLongValue = ((Long) obj2).longValue();
                Intrinsics.checkNotNullParameter(payload, "payload");
                return new e(sVar.k(payload, jLongValue, false), 3);
            case 2:
                MediaPlayer player = (MediaPlayer) obj;
                Intrinsics.checkNotNullParameter(player, "player");
                com.quizlet.quizletandroid.audio.players.h hVar = (com.quizlet.quizletandroid.audio.players.h) this.b;
                hVar.getClass();
                c cVar = new c(new com.google.firebase.tracing.a(22, hVar, player), 1);
                Intrinsics.checkNotNullExpressionValue(cVar, "create(...)");
                return cVar;
            case 3:
                Intrinsics.checkNotNullParameter((List) obj, "<unused var>");
                return (List) this.b;
            case 4:
                com.quizlet.quizletandroid.data.management.a info = (com.quizlet.quizletandroid.data.management.a) obj;
                Intrinsics.checkNotNullParameter(info, "p0");
                s sVar2 = (s) this.b;
                Intrinsics.checkNotNullParameter(info, "info");
                com.quizlet.infra.legacysyncengine.orm.b bVar = new com.quizlet.infra.legacysyncengine.orm.b(Models.TERM);
                bVar.b(Long.valueOf(info.a.getId()), DBTermFields.SET);
                com.quizlet.infra.legacysyncengine.orm.query.a aVarA = bVar.a();
                Intrinsics.checkNotNullExpressionValue(aVarA, "build(...)");
                int i = 3;
                j jVar = new j(new j(new io.reactivex.rxjava3.internal.operators.maybe.h(i, ((s) sVar2.e).h(((QueryIdFieldChangeMapper) sVar2.d).convertStaleLocalIds(aVarA)).f(), new com.google.firebase.crashlytics.internal.common.j(info, 28)), new androidx.work.impl.model.e(26, sVar2, info), 0), new com.quizlet.local.ormlite.models.term.b(info, 5), 1);
                Intrinsics.checkNotNullExpressionValue(jVar, "map(...)");
                return jVar;
            case 5:
                C request = (C) obj;
                Intrinsics.checkNotNullParameter(request, "p0");
                A a = (A) this.b;
                Intrinsics.checkNotNullParameter(a, "<this>");
                Intrinsics.checkNotNullParameter(request, "request");
                g call = a.c(request);
                Intrinsics.checkNotNullParameter(a, "<this>");
                Intrinsics.checkNotNullParameter(call, "call");
                io.reactivex.rxjava3.internal.operators.flowable.b bVar2 = new io.reactivex.rxjava3.internal.operators.flowable.b(new com.google.android.material.search.a(call, 28), 3);
                Intrinsics.checkNotNullExpressionValue(bVar2, "create(...)");
                return bVar2;
            case 6:
                File file = (File) obj;
                Intrinsics.checkNotNullParameter(file, "it");
                com.quizlet.quizletandroid.audio.players.h hVar2 = ((com.quizlet.quizletandroid.managers.audio.h) this.b).b;
                hVar2.getClass();
                Intrinsics.checkNotNullParameter(file, "file");
                timber.log.a aVar = timber.log.c.a;
                aVar.g(AbstractC0147y.d("Starting playFile flow for file ", file.getPath()), new Object[0]);
                hVar2.c();
                hVar2.d.b(Unit.a);
                MediaPlayer mediaPlayer = hVar2.b;
                if (mediaPlayer == null) {
                    aVar.g("Initializing new MediaPlayer instance...", new Object[0]);
                    mediaPlayer = new MediaPlayer();
                    hVar2.b = mediaPlayer;
                }
                io.reactivex.rxjava3.internal.operators.flowable.b bVar3 = new io.reactivex.rxjava3.internal.operators.flowable.b(new com.quizlet.data.repository.folderwithcreator.a(file, hVar2, mediaPlayer, 1), 4);
                Intrinsics.checkNotNullExpressionValue(bVar3, "with(...)");
                io.reactivex.rxjava3.internal.operators.completable.a aVar2 = new io.reactivex.rxjava3.internal.operators.completable.a(5, bVar3, new a(hVar2, 2));
                Intrinsics.checkNotNullExpressionValue(aVar2, "flatMapCompletable(...)");
                return aVar2;
            case 7:
            case 8:
            case 9:
            case 10:
            case 11:
            default:
                List bookmarkedFolderIds = (List) obj;
                Intrinsics.checkNotNullParameter(bookmarkedFolderIds, "bookmarkedFolderIds");
                if (!bookmarkedFolderIds.isEmpty()) {
                    return ((m) ((com.quizlet.remote.model.union.folderwithcreator.b) this.b).a).g(U.c(bookmarkedFolderIds), false);
                }
                return p.f(new ApiThreeWrapper(null, 0 == true ? 1 : 0, 3, 0 == true ? 1 : 0));
            case 12:
                Pair pair2 = (Pair) obj;
                Intrinsics.checkNotNullParameter(pair2, "<destruct>");
                Object obj3 = pair2.a;
                Intrinsics.checkNotNullExpressionValue(obj3, "component1(...)");
                List list = (List) obj3;
                Object obj4 = pair2.b;
                Intrinsics.checkNotNullExpressionValue(obj4, "component2(...)");
                Boolean bool = (Boolean) obj4;
                if (list.isEmpty()) {
                    return kotlin.collections.K.a;
                }
                List<B0> listP0 = CollectionsKt.p0(list, 6);
                boolean zBooleanValue = bool.booleanValue();
                ((androidx.work.impl.model.e) this.b).getClass();
                ArrayList arrayList = new ArrayList(kotlin.collections.C.q(listP0, 10));
                for (B0 b0 : listP0) {
                    arrayList.add(new F(b0, zBooleanValue, b0.getItemId(), b0.b(), w1.RECENT_FEED));
                }
                return kotlin.collections.A.b(new com.quizlet.quizletandroid.ui.startpage.nav2.model.A(arrayList));
        }
    }

    @Override // com.quizlet.features.infra.legacyadapter.d
    public /* bridge */ /* synthetic */ boolean b(View view, int i, DBModel dBModel) {
        switch (this.a) {
            case 8:
                break;
            default:
                break;
        }
        return false;
    }

    @Override // com.quizlet.quizletandroid.ui.common.ads.InterfaceC4638e
    public void c() {
        ((com.pubmatic.sdk.openwrap.banner.c) this.b).loadAd();
    }

    @Override // com.quizlet.features.infra.legacyadapter.d
    public boolean d(View view, int i, DBModel dBModel) throws Exception {
        switch (this.a) {
            case 8:
                DBUser dBUser = (DBUser) dBModel;
                if (dBUser != null) {
                    ClassUserListFragment classUserListFragment = (ClassUserListFragment) this.b;
                    classUserListFragment.startActivityForResult(ProfileActivity.p.g(classUserListFragment.getContext(), dBUser.getId()), 201);
                    break;
                }
                break;
            default:
                DBGroup dBGroup = (DBGroup) dBModel;
                if (dBGroup != null) {
                    ((UserClassListFragment) this.b).f0(dBGroup.getId());
                    break;
                }
                break;
        }
        return true;
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object e(long r5, kotlin.coroutines.jvm.internal.c r7) {
        /*
            r4 = this;
            boolean r0 = r7 instanceof com.quizlet.remote.model.folder.a
            if (r0 == 0) goto L13
            r0 = r7
            com.quizlet.remote.model.folder.a r0 = (com.quizlet.remote.model.folder.a) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            com.quizlet.remote.model.folder.a r0 = new com.quizlet.remote.model.folder.a
            r0.<init>(r4, r7)
        L18:
            java.lang.Object r7 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 1
            if (r2 == 0) goto L2f
            if (r2 != r3) goto L27
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L43
        L27:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L2f:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            java.lang.Object r7 = r4.b
            com.quizlet.remote.service.m r7 = (com.quizlet.remote.service.m) r7
            io.reactivex.rxjava3.core.p r5 = r7.a(r5)
            r0.l = r3
            java.lang.Object r7 = com.google.android.gms.internal.mlkit_vision_camera.I1.b(r5, r0)
            if (r7 != r1) goto L43
            return r1
        L43:
            java.lang.String r5 = "await(...)"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r7, r5)
            return r7
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.login.authentication.login.a.e(long, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object f(long r5, java.util.List r7, kotlin.coroutines.jvm.internal.c r8) {
        /*
            r4 = this;
            boolean r0 = r8 instanceof com.quizlet.remote.model.folder.b
            if (r0 == 0) goto L13
            r0 = r8
            com.quizlet.remote.model.folder.b r0 = (com.quizlet.remote.model.folder.b) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            com.quizlet.remote.model.folder.b r0 = new com.quizlet.remote.model.folder.b
            r0.<init>(r4, r8)
        L18:
            java.lang.Object r8 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 1
            if (r2 == 0) goto L2f
            if (r2 != r3) goto L27
            androidx.glance.appwidget.protobuf.Z.e(r8)
            goto L48
        L27:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L2f:
            androidx.glance.appwidget.protobuf.Z.e(r8)
            com.quizlet.remote.model.base.ApiPostBody r8 = new com.quizlet.remote.model.base.ApiPostBody
            r8.<init>(r7)
            java.lang.Object r7 = r4.b
            com.quizlet.remote.service.m r7 = (com.quizlet.remote.service.m) r7
            io.reactivex.rxjava3.core.p r5 = r7.f(r5, r8)
            r0.l = r3
            java.lang.Object r8 = com.google.android.gms.internal.mlkit_vision_camera.I1.b(r5, r0)
            if (r8 != r1) goto L48
            return r1
        L48:
            java.lang.String r5 = "await(...)"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r8, r5)
            return r8
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.login.authentication.login.a.f(long, java.util.List, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object g(long r5, kotlin.coroutines.jvm.internal.c r7) {
        /*
            r4 = this;
            boolean r0 = r7 instanceof com.quizlet.remote.model.folder.c
            if (r0 == 0) goto L13
            r0 = r7
            com.quizlet.remote.model.folder.c r0 = (com.quizlet.remote.model.folder.c) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            com.quizlet.remote.model.folder.c r0 = new com.quizlet.remote.model.folder.c
            r0.<init>(r4, r7)
        L18:
            java.lang.Object r7 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 1
            if (r2 == 0) goto L2f
            if (r2 != r3) goto L27
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L43
        L27:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L2f:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            java.lang.Object r7 = r4.b
            com.quizlet.remote.service.m r7 = (com.quizlet.remote.service.m) r7
            io.reactivex.rxjava3.core.p r5 = r7.c(r5)
            r0.l = r3
            java.lang.Object r7 = com.google.android.gms.internal.mlkit_vision_camera.I1.b(r5, r0)
            if (r7 != r1) goto L43
            return r1
        L43:
            java.lang.String r5 = "await(...)"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r7, r5)
            return r7
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.login.authentication.login.a.g(long, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object h(long r5, kotlin.coroutines.jvm.internal.c r7) {
        /*
            r4 = this;
            boolean r0 = r7 instanceof com.quizlet.remote.model.folder.d
            if (r0 == 0) goto L13
            r0 = r7
            com.quizlet.remote.model.folder.d r0 = (com.quizlet.remote.model.folder.d) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            com.quizlet.remote.model.folder.d r0 = new com.quizlet.remote.model.folder.d
            r0.<init>(r4, r7)
        L18:
            java.lang.Object r7 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 1
            if (r2 == 0) goto L2f
            if (r2 != r3) goto L27
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L47
        L27:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L2f:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            java.lang.Object r7 = r4.b
            com.quizlet.remote.service.m r7 = (com.quizlet.remote.service.m) r7
            java.lang.String r5 = java.lang.String.valueOf(r5)
            io.reactivex.rxjava3.core.p r5 = r7.d(r5)
            r0.l = r3
            java.lang.Object r7 = com.google.android.gms.internal.mlkit_vision_camera.I1.b(r5, r0)
            if (r7 != r1) goto L47
            return r1
        L47:
            java.lang.String r5 = "await(...)"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r7, r5)
            return r7
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.login.authentication.login.a.h(long, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    @Override // com.quizlet.quizletandroid.ui.common.ads.InterfaceC4638e
    public void i() {
        ((com.pubmatic.sdk.openwrap.banner.c) this.b).proceedToLoadAd();
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object j(long r5, kotlin.coroutines.jvm.internal.c r7) {
        /*
            r4 = this;
            boolean r0 = r7 instanceof com.quizlet.remote.model.folder.e
            if (r0 == 0) goto L13
            r0 = r7
            com.quizlet.remote.model.folder.e r0 = (com.quizlet.remote.model.folder.e) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            com.quizlet.remote.model.folder.e r0 = new com.quizlet.remote.model.folder.e
            r0.<init>(r4, r7)
        L18:
            java.lang.Object r7 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 1
            if (r2 == 0) goto L2f
            if (r2 != r3) goto L27
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L43
        L27:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L2f:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            java.lang.Object r7 = r4.b
            com.quizlet.remote.service.m r7 = (com.quizlet.remote.service.m) r7
            io.reactivex.rxjava3.core.p r5 = r7.b(r5)
            r0.l = r3
            java.lang.Object r7 = com.google.android.gms.internal.mlkit_vision_camera.I1.b(r5, r0)
            if (r7 != r1) goto L43
            return r1
        L43:
            java.lang.String r5 = "await(...)"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r7, r5)
            return r7
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.login.authentication.login.a.j(long, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object k(com.quizlet.features.infra.basestudy.manager.f r7, kotlin.coroutines.jvm.internal.c r8) {
        /*
            r6 = this;
            boolean r0 = r8 instanceof com.quizlet.quizletandroid.ui.studymodes.assistant.settings.interaction.a
            if (r0 == 0) goto L13
            r0 = r8
            com.quizlet.quizletandroid.ui.studymodes.assistant.settings.interaction.a r0 = (com.quizlet.quizletandroid.ui.studymodes.assistant.settings.interaction.a) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            com.quizlet.quizletandroid.ui.studymodes.assistant.settings.interaction.a r0 = new com.quizlet.quizletandroid.ui.studymodes.assistant.settings.interaction.a
            r0.<init>(r6, r8)
        L18:
            java.lang.Object r8 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 1
            if (r2 == 0) goto L2f
            if (r2 != r3) goto L27
            androidx.glance.appwidget.protobuf.Z.e(r8)
            goto L50
        L27:
            java.lang.IllegalStateException r7 = new java.lang.IllegalStateException
            java.lang.String r8 = "call to 'resume' before 'invoke' with coroutine"
            r7.<init>(r8)
            throw r7
        L2f:
            androidx.glance.appwidget.protobuf.Z.e(r8)
            com.quizlet.features.infra.studysetting.managers.a r8 = r7.g()
            r8.getClass()
            com.quizlet.generated.enums.E1 r2 = com.quizlet.generated.enums.E1.GUIDANCE_DISABLED
            boolean r8 = com.quizlet.features.infra.studysetting.managers.a.d(r8, r2)
            if (r8 != 0) goto L56
            r0.l = r3
            java.lang.Object r8 = r6.b
            com.google.android.gms.measurement.internal.J r8 = (com.google.android.gms.measurement.internal.J) r8
            long r4 = r7.u
            java.lang.Enum r8 = r8.e(r4, r0)
            if (r8 != r1) goto L50
            return r1
        L50:
            com.quizlet.featuregate.features.studymodes.learn.b r7 = com.quizlet.featuregate.features.studymodes.learn.b.b
            if (r8 != r7) goto L55
            goto L56
        L55:
            r3 = 0
        L56:
            java.lang.Boolean r7 = java.lang.Boolean.valueOf(r3)
            return r7
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.login.authentication.login.a.k(com.quizlet.features.infra.basestudy.manager.f, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public boolean l() {
        return ((androidx.lifecycle.viewmodel.c) this.b) == null;
    }

    @Override // io.reactivex.rxjava3.core.b
    public void onComplete() {
        ((b) this.b).onComplete();
    }

    @Override // io.reactivex.rxjava3.core.b
    public void onError(Throwable th) {
        ((b) this.b).onComplete();
    }

    public a(J getLearnTaskVariantUseCase) {
        this.a = 13;
        Intrinsics.checkNotNullParameter(getLearnTaskVariantUseCase, "getLearnTaskVariantUseCase");
        this.b = getLearnTaskVariantUseCase;
    }

    public a(com.quizlet.remote.service.s service) {
        this.a = 17;
        Intrinsics.checkNotNullParameter(service, "service");
        this.b = service;
    }

    public a(m service) {
        this.a = 16;
        Intrinsics.checkNotNullParameter(service, "service");
        this.b = service;
    }

    public a(InterfaceC4776c service) {
        this.a = 15;
        Intrinsics.checkNotNullParameter(service, "service");
        this.b = service;
    }

    public a(int i) {
        this.a = i;
        switch (i) {
            case 19:
                break;
            default:
                this.b = kotlin.random.e.a;
                break;
        }
    }

    public a(com.pubmatic.sdk.openwrap.banner.c view) {
        this.a = 7;
        Intrinsics.checkNotNullParameter(view, "view");
        this.b = view;
    }

    public a(okhttp3.internal.a threadFactory) {
        this.a = 21;
        Intrinsics.checkNotNullParameter(threadFactory, "threadFactory");
        this.b = new ThreadPoolExecutor(0, SubsamplingScaleImageView.TILE_SIZE_AUTO, 60L, TimeUnit.SECONDS, new SynchronousQueue(), threadFactory);
    }
}
