package com.quizlet.data.repository.explanations.myexplanations;

import android.content.Context;
import android.content.res.Resources;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewGroup;
import androidx.appcompat.widget.SearchView;
import androidx.appcompat.widget.d1;
import androidx.camera.core.C0152d;
import androidx.camera.core.ProcessingException;
import androidx.camera.core.impl.D;
import androidx.camera.core.impl.utils.futures.c;
import androidx.camera.core.processing.k;
import androidx.compose.foundation.text.selection.n0;
import androidx.compose.runtime.saveable.l;
import androidx.compose.ui.text.C0995g;
import androidx.compose.ui.text.K;
import androidx.compose.ui.text.input.A;
import androidx.compose.ui.text.input.C1007j;
import androidx.compose.ui.text.input.InterfaceC1006i;
import androidx.lifecycle.Y;
import androidx.paging.C1329n;
import androidx.work.impl.utils.q;
import com.comscore.streaming.EventType;
import com.google.android.datatransport.cct.internal.s;
import com.google.android.gms.common.api.ApiException;
import com.google.android.gms.common.api.Status;
import com.google.android.gms.common.api.internal.BasePendingResult;
import com.google.android.gms.internal.ads.C1721Kc;
import com.google.android.gms.internal.ads.C3;
import com.google.android.gms.internal.measurement.AbstractC3053s1;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3205m5;
import com.google.android.gms.internal.mlkit_vision_barcode.U;
import com.google.android.gms.internal.mlkit_vision_camera.i3;
import com.google.android.material.floatingactionbutton.ExtendedFloatingActionButton;
import com.google.android.material.floatingactionbutton.g;
import com.quizlet.billing.subscriptions.i;
import com.quizlet.billing.subscriptions.j;
import com.quizlet.data.model.EnumC4159q0;
import com.quizlet.data.model.i2;
import com.quizlet.data.repository.set.f;
import com.quizlet.db.data.caches.UserInfoCache;
import com.quizlet.db.data.models.persisted.DBGroupSet;
import com.quizlet.db.data.models.persisted.DBTerm;
import com.quizlet.eventlogger.EventLogger;
import com.quizlet.eventlogger.features.folder.FolderLogger;
import com.quizlet.partskit.widgets.QButton;
import com.quizlet.quizletandroid.C4622e;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.u;
import com.quizlet.quizletandroid.ui.setcreation.activities.EditSetLanguageSelectionActivity;
import com.quizlet.quizletandroid.ui.setcreation.managers.n;
import com.quizlet.quizletandroid.ui.studymodes.testmode.fragments.TestStudyModeResultsLoadingFragment;
import com.quizlet.quizletandroid.ui.studymodes.write.WriteModeCheckPointView;
import com.quizlet.qutils.data.offline.d;
import dagger.android.b;
import io.reactivex.rxjava3.core.p;
import io.reactivex.rxjava3.functions.h;
import io.reactivex.rxjava3.internal.operators.maybe.e;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.WeakHashMap;
import java.util.concurrent.CancellationException;
import java.util.concurrent.atomic.AtomicInteger;
import kotlin.Pair;
import kotlin.collections.C;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.AbstractC5040y;
import kotlinx.coroutines.flow.e0;
import kotlinx.coroutines.flow.s0;

/* loaded from: classes2.dex */
public final class a implements c, l, g, h, b, d1 {
    public final /* synthetic */ int a;
    public Object b;
    public Object c;

    public /* synthetic */ a(int i, Object obj, Object obj2) {
        this.a = i;
        this.c = obj;
        this.b = obj2;
    }

    @Override // androidx.compose.runtime.saveable.l
    public Object a(androidx.compose.runtime.saveable.b bVar, Object obj) {
        return ((Function2) this.b).invoke(bVar, obj);
    }

    @Override // io.reactivex.rxjava3.functions.h
    public Object apply(Object obj) {
        com.quizlet.data.model.billing.a aVar;
        Map map;
        switch (this.a) {
            case 14:
                com.quizlet.billing.model.a inventory = (com.quizlet.billing.model.a) obj;
                Intrinsics.checkNotNullParameter(inventory, "inventory");
                com.google.android.material.floatingactionbutton.c cVar = ((i) this.b).b;
                j subscriptionPackage = (j) this.c;
                Intrinsics.checkNotNullParameter(subscriptionPackage, "subscriptionPackage");
                Intrinsics.checkNotNullParameter(inventory, "inventory");
                String sku = ((com.quizlet.billing.manager.sku.a) cVar.b).a(subscriptionPackage);
                Intrinsics.checkNotNullParameter(sku, "sku");
                if (inventory != null) {
                    Intrinsics.checkNotNullParameter(sku, "sku");
                    aVar = (com.quizlet.data.model.billing.a) inventory.a.get(sku);
                } else {
                    aVar = null;
                }
                return com.google.android.gms.common.wrappers.a.d(aVar);
            case EventType.WINDOW_STATE /* 22 */:
                Map preexistingIdMap = (Map) obj;
                Intrinsics.checkNotNullParameter(preexistingIdMap, "preexistingIdMap");
                ArrayList arrayList = (ArrayList) this.b;
                Iterator it2 = arrayList.iterator();
                while (it2.hasNext()) {
                    DBGroupSet dBGroupSet = (DBGroupSet) it2.next();
                    ((com.quizlet.local.ormlite.models.bookmark.a) this.c).getClass();
                    Long l = (Long) preexistingIdMap.get(new com.quizlet.data.repository.classset.a(dBGroupSet.getClassId(), dBGroupSet.getSetId()));
                    if (l != null) {
                        dBGroupSet.setLocalId(l.longValue());
                    }
                }
                return arrayList;
            case EventType.AUDIO /* 23 */:
                Map serverIdToLocalIdMap = (Map) obj;
                Intrinsics.checkNotNullParameter(serverIdToLocalIdMap, "serverIdToLocalIdMap");
                ((f) this.b).getClass();
                List<i2> list = (List) this.c;
                ArrayList arrayList2 = new ArrayList(C.q(list, 10));
                for (i2 i2Var : list) {
                    Long l2 = (Long) serverIdToLocalIdMap.get(Long.valueOf(i2Var.a));
                    if (l2 != null) {
                        long jLongValue = l2.longValue();
                        String word = i2Var.e;
                        Intrinsics.checkNotNullParameter(word, "word");
                        map = serverIdToLocalIdMap;
                        i2Var = new i2(i2Var.a, jLongValue, i2Var.c, i2Var.d, word, i2Var.f, i2Var.g, i2Var.h, i2Var.i, i2Var.j, i2Var.k);
                    } else {
                        map = serverIdToLocalIdMap;
                    }
                    arrayList2.add(i2Var);
                    serverIdToLocalIdMap = map;
                }
                return arrayList2;
            default:
                List<DBTerm> list2 = (List) obj;
                Intrinsics.checkNotNullParameter(list2, "list");
                HashSet hashSet = new HashSet();
                for (DBTerm dBTerm : list2) {
                    String definitionAudioUrl = dBTerm.getDefinitionAudioUrl();
                    String wordAudioUrl = dBTerm.getWordAudioUrl();
                    if (definitionAudioUrl != null) {
                        hashSet.add(definitionAudioUrl);
                    }
                    if (wordAudioUrl != null) {
                        hashSet.add(wordAudioUrl);
                    }
                }
                List listP0 = CollectionsKt.p0(hashSet, 400);
                com.quizlet.quizletandroid.data.management.a aVar2 = (com.quizlet.quizletandroid.data.management.a) this.c;
                d dVar = aVar2.b;
                s sVar = (s) this.b;
                return new e(s.a(sVar, listP0, dVar, (com.quizlet.quizletandroid.managers.audio.g) sVar.b).g(new com.quizlet.data.repository.classfolder.e(aVar2, listP0, hashSet, 14)), 3);
        }
    }

    @Override // com.google.android.material.floatingactionbutton.g
    public int b() {
        ViewGroup.MarginLayoutParams marginLayoutParams;
        ExtendedFloatingActionButton extendedFloatingActionButton = (ExtendedFloatingActionButton) this.c;
        int i = extendedFloatingActionButton.H;
        ExtendedFloatingActionButton extendedFloatingActionButton2 = (ExtendedFloatingActionButton) ((com.google.android.material.floatingactionbutton.c) this.b).b;
        if (i != -1) {
            return (i == 0 || i == -2) ? extendedFloatingActionButton2.getMeasuredHeight() : i;
        }
        if (!(extendedFloatingActionButton.getParent() instanceof View)) {
            return extendedFloatingActionButton2.getMeasuredHeight();
        }
        View view = (View) extendedFloatingActionButton.getParent();
        ViewGroup.LayoutParams layoutParams = view.getLayoutParams();
        if (layoutParams == null || layoutParams.height != -2) {
            return (view.getHeight() - ((!(extendedFloatingActionButton.getLayoutParams() instanceof ViewGroup.MarginLayoutParams) || (marginLayoutParams = (ViewGroup.MarginLayoutParams) extendedFloatingActionButton.getLayoutParams()) == null) ? 0 : marginLayoutParams.topMargin + marginLayoutParams.bottomMargin)) - (view.getPaddingBottom() + view.getPaddingTop());
        }
        return extendedFloatingActionButton2.getMeasuredHeight();
    }

    @Override // androidx.appcompat.widget.d1
    public boolean c(String str) {
        com.quizlet.quizletandroid.ui.setcreation.adapters.c cVar = ((EditSetLanguageSelectionActivity) this.c).t;
        cVar.getClass();
        new androidx.cursoradapter.widget.b(cVar).filter(str);
        return true;
    }

    @Override // dagger.android.b
    public void d(Object obj) {
        TestStudyModeResultsLoadingFragment testStudyModeResultsLoadingFragment = (TestStudyModeResultsLoadingFragment) obj;
        C4622e c4622e = (C4622e) this.c;
        testStudyModeResultsLoadingFragment.a = c4622e.a();
        testStudyModeResultsLoadingFragment.b = ((u) this.b).S0();
        c4622e.e();
    }

    @Override // androidx.appcompat.widget.d1
    public boolean e(String str) {
        EditSetLanguageSelectionActivity editSetLanguageSelectionActivity = (EditSetLanguageSelectionActivity) this.c;
        SearchView searchView = editSetLanguageSelectionActivity.u;
        if (!searchView.c1) {
            searchView.setIconified(true);
        }
        ((MenuItem) this.b).collapseActionView();
        com.quizlet.quizletandroid.ui.setcreation.adapters.c cVar = editSetLanguageSelectionActivity.t;
        cVar.getClass();
        new androidx.cursoradapter.widget.b(cVar).filter(str);
        com.bumptech.glide.c.C(editSetLanguageSelectionActivity.u, false);
        return true;
    }

    public boolean equals(Object obj) {
        switch (this.a) {
            case 6:
                if (!(obj instanceof androidx.core.util.c)) {
                    return false;
                }
                androidx.core.util.c cVar = (androidx.core.util.c) obj;
                Object obj2 = cVar.a;
                String str = (String) this.b;
                if (obj2 != str && (obj2 == null || !obj2.equals(str))) {
                    return false;
                }
                Object obj3 = cVar.b;
                String str2 = (String) this.c;
                return obj3 == str2 || (obj3 != null && obj3.equals(str2));
            default:
                return super.equals(obj);
        }
    }

    public A f(List list) {
        InterfaceC1006i interfaceC1006i;
        Exception e;
        InterfaceC1006i interfaceC1006i2;
        try {
            int size = list.size();
            int i = 0;
            interfaceC1006i = null;
            while (i < size) {
                try {
                    interfaceC1006i2 = (InterfaceC1006i) list.get(i);
                } catch (Exception e2) {
                    e = e2;
                }
                try {
                    interfaceC1006i2.a((C1007j) this.c);
                    i++;
                    interfaceC1006i = interfaceC1006i2;
                } catch (Exception e3) {
                    e = e3;
                    interfaceC1006i = interfaceC1006i2;
                    StringBuilder sb = new StringBuilder();
                    StringBuilder sb2 = new StringBuilder("Error while applying EditCommand batch to buffer (length=");
                    sb2.append(((androidx.compose.ui.text.android.selection.f) ((C1007j) this.c).f).d());
                    sb2.append(", composition=");
                    sb2.append(((C1007j) this.c).d());
                    sb2.append(", selection=");
                    C1007j c1007j = (C1007j) this.c;
                    sb2.append((Object) K.g(AbstractC3205m5.c(c1007j.b, c1007j.c)));
                    sb2.append("):");
                    sb.append(sb2.toString());
                    Intrinsics.checkNotNullExpressionValue(sb, "append(value)");
                    sb.append('\n');
                    Intrinsics.checkNotNullExpressionValue(sb, "append('\\n')");
                    CollectionsKt.R(list, sb, "\n", new n0(28, interfaceC1006i, this), 60);
                    String string = sb.toString();
                    Intrinsics.checkNotNullExpressionValue(string, "StringBuilder().apply(builderAction).toString()");
                    throw new RuntimeException(string, e);
                }
            }
            C1007j c1007j2 = (C1007j) this.c;
            c1007j2.getClass();
            C0995g c0995g = new C0995g(6, ((androidx.compose.ui.text.android.selection.f) c1007j2.f).toString(), null);
            C1007j c1007j3 = (C1007j) this.c;
            long jC = AbstractC3205m5.c(c1007j3.b, c1007j3.c);
            K k = K.f(((A) this.b).b) ? null : new K(jC);
            A a = new A(c0995g, k != null ? k.a : AbstractC3205m5.c(K.d(jC), K.e(jC)), ((C1007j) this.c).d());
            this.b = a;
            return a;
        } catch (Exception e4) {
            interfaceC1006i = null;
            e = e4;
        }
    }

    public io.reactivex.rxjava3.internal.operators.single.g g(Integer num, List filters, p stopToken) {
        Intrinsics.checkNotNullParameter(filters, "filters");
        Intrinsics.checkNotNullParameter(stopToken, "stopToken");
        Intrinsics.checkNotNullParameter(filters, "filters");
        Intrinsics.checkNotNullParameter(stopToken, "stopToken");
        io.reactivex.rxjava3.internal.operators.single.g gVarG = ((androidx.work.impl.model.c) this.c).c(stopToken, new q(this, num, filters, 7)).g(com.quizlet.data.interactor.explanations.myexplanations.b.a);
        Intrinsics.checkNotNullExpressionValue(gVarG, "map(...)");
        return gVarG;
    }

    @Override // com.google.android.material.floatingactionbutton.g
    public ViewGroup.LayoutParams getLayoutParams() {
        int i = ((ExtendedFloatingActionButton) this.c).H;
        if (i == 0) {
            i = -2;
        }
        return new ViewGroup.LayoutParams(-1, i);
    }

    @Override // com.google.android.material.floatingactionbutton.g
    public int getWidth() {
        ViewGroup.MarginLayoutParams marginLayoutParams;
        ExtendedFloatingActionButton extendedFloatingActionButton = (ExtendedFloatingActionButton) this.c;
        boolean z = extendedFloatingActionButton.getParent() instanceof View;
        com.google.android.material.floatingactionbutton.c cVar = (com.google.android.material.floatingactionbutton.c) this.b;
        if (!z) {
            return cVar.getWidth();
        }
        View view = (View) extendedFloatingActionButton.getParent();
        ViewGroup.LayoutParams layoutParams = view.getLayoutParams();
        if (layoutParams == null || layoutParams.width != -2) {
            return (view.getWidth() - ((!(extendedFloatingActionButton.getLayoutParams() instanceof ViewGroup.MarginLayoutParams) || (marginLayoutParams = (ViewGroup.MarginLayoutParams) extendedFloatingActionButton.getLayoutParams()) == null) ? 0 : marginLayoutParams.leftMargin + marginLayoutParams.rightMargin)) - (view.getPaddingRight() + view.getPaddingLeft());
        }
        return cVar.getWidth();
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object h(long r5, kotlin.coroutines.jvm.internal.c r7) throws java.lang.Throwable {
        /*
            r4 = this;
            boolean r0 = r7 instanceof com.quizlet.data.interactor.folder.s
            if (r0 == 0) goto L13
            r0 = r7
            com.quizlet.data.interactor.folder.s r0 = (com.quizlet.data.interactor.folder.s) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            com.quizlet.data.interactor.folder.s r0 = new com.quizlet.data.interactor.folder.s
            r0.<init>(r4, r7)
        L18:
            java.lang.Object r7 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 1
            if (r2 == 0) goto L2f
            if (r2 != r3) goto L27
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L45
        L27:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L2f:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            com.quizlet.data.interactor.folder.t r7 = new com.quizlet.data.interactor.folder.t
            r2 = 0
            r7.<init>(r4, r5, r2)
            r0.l = r3
            java.lang.Object r5 = r4.c
            kotlinx.coroutines.y r5 = (kotlinx.coroutines.AbstractC5040y) r5
            java.lang.Object r7 = kotlinx.coroutines.E.J(r5, r7, r0)
            if (r7 != r1) goto L45
            return r1
        L45:
            kotlin.r r7 = (kotlin.r) r7
            java.lang.Object r5 = r7.a
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.repository.explanations.myexplanations.a.h(long, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public int hashCode() {
        switch (this.a) {
            case 6:
                String str = (String) this.b;
                int iHashCode = str == null ? 0 : str.hashCode();
                String str2 = (String) this.c;
                return iHashCode ^ (str2 != null ? str2.hashCode() : 0);
            default:
                return super.hashCode();
        }
    }

    @Override // com.google.android.material.floatingactionbutton.g
    public int i() {
        return ((ExtendedFloatingActionButton) this.c).A;
    }

    public void j(String str) {
        com.bumptech.glide.load.engine.cache.b bVar;
        synchronized (this) {
            try {
                Object obj = ((HashMap) this.b).get(str);
                com.bumptech.glide.util.f.c(obj, "Argument must not be null");
                bVar = (com.bumptech.glide.load.engine.cache.b) obj;
                int i = bVar.b;
                if (i < 1) {
                    throw new IllegalStateException("Cannot release a lock that is not held, safeKey: " + str + ", interestedThreads: " + bVar.b);
                }
                int i2 = i - 1;
                bVar.b = i2;
                if (i2 == 0) {
                    com.bumptech.glide.load.engine.cache.b bVar2 = (com.bumptech.glide.load.engine.cache.b) ((HashMap) this.b).remove(str);
                    if (!bVar2.equals(bVar)) {
                        throw new IllegalStateException("Removed the wrong lock, expected to remove: " + bVar + ", but actually removed: " + bVar2 + ", safeKey: " + str);
                    }
                    com.airbnb.lottie.network.d dVar = (com.airbnb.lottie.network.d) this.c;
                    synchronized (((ArrayDeque) dVar.b)) {
                        if (((ArrayDeque) dVar.b).size() < 10) {
                            ((ArrayDeque) dVar.b).offer(bVar2);
                        }
                    }
                }
            } catch (Throwable th) {
                throw th;
            }
        }
        bVar.a.unlock();
    }

    public void k(Object data) {
        Intrinsics.checkNotNullParameter(data, "data");
        s0 s0Var = (s0) this.b;
        Pair pair = new Pair(Integer.valueOf(((Number) ((Pair) s0Var.getValue()).a).intValue() + 1), data);
        s0Var.getClass();
        s0Var.m(null, pair);
    }

    public EnumC4159q0 l(String tag) {
        Intrinsics.checkNotNullParameter(tag, "tag");
        return tag.length() <= 25 ? EnumC4159q0.a : EnumC4159q0.b;
    }

    public void m(boolean z, Status status) {
        HashMap map;
        HashMap map2;
        Map map3 = (Map) this.b;
        synchronized (map3) {
            map = new HashMap(map3);
        }
        Map map4 = (Map) this.c;
        synchronized (map4) {
            map2 = new HashMap(map4);
        }
        for (Map.Entry entry : map.entrySet()) {
            if (z || ((Boolean) entry.getValue()).booleanValue()) {
                ((BasePendingResult) entry.getKey()).forceFailureUnlessReady(status);
            }
        }
        for (Map.Entry entry2 : map2.entrySet()) {
            if (z || ((Boolean) entry2.getValue()).booleanValue()) {
                ((com.google.android.gms.tasks.f) entry2.getKey()).c(new ApiException(status));
            }
        }
    }

    @Override // androidx.camera.core.impl.utils.futures.c
    public void onFailure(Throwable th) {
        int i = ((k) this.b).f;
        if (i == 2 && (th instanceof CancellationException)) {
            AbstractC3053s1.f(3, "SurfaceProcessorNode");
            return;
        }
        AbstractC3053s1.i("SurfaceProcessorNode", "Downstream node failed to provide Surface. Target: " + U.b(i), th);
    }

    @Override // androidx.camera.core.impl.utils.futures.c, io.reactivex.rxjava3.core.q, com.google.android.gms.tasks.d
    public void onSuccess(Object obj) {
        androidx.camera.core.processing.l lVar = (androidx.camera.core.processing.l) obj;
        lVar.getClass();
        try {
            ((androidx.camera.core.processing.c) ((io.ktor.client.plugins.api.d) this.c).b).b(lVar);
        } catch (ProcessingException e) {
            AbstractC3053s1.d("SurfaceProcessorNode", "Failed to send SurfaceOutput to SurfaceProcessor.", e);
        }
    }

    public String toString() {
        switch (this.a) {
            case 6:
                StringBuilder sb = new StringBuilder("Pair{");
                sb.append(this.b);
                sb.append(" ");
                sb.append(this.c);
                sb.append("}");
                return sb.toString();
            default:
                return super.toString();
        }
    }

    @Override // com.google.android.material.floatingactionbutton.g
    public int v() {
        return ((ExtendedFloatingActionButton) this.c).z;
    }

    public /* synthetic */ a(int i, boolean z) {
        this.a = i;
    }

    public /* synthetic */ a(Object obj, boolean z, Object obj2, int i) {
        this.a = i;
        this.b = obj;
        this.c = obj2;
    }

    public a(io.ktor.client.plugins.api.d dVar) {
        this.a = 10;
        this.c = new C3();
        this.b = dVar;
        i3.b();
    }

    public a(com.quizlet.local.ormlite.models.bookmark.a classFolderLocalDataStore, com.quizlet.data.repository.widget.b classFolderRemoteDataStore) {
        this.a = 18;
        Intrinsics.checkNotNullParameter(classFolderLocalDataStore, "classFolderLocalDataStore");
        Intrinsics.checkNotNullParameter(classFolderRemoteDataStore, "classFolderRemoteDataStore");
        this.b = classFolderLocalDataStore;
        this.c = classFolderRemoteDataStore;
    }

    public a(C3 practiceTestsRepository, UserInfoCache userInfoCache) {
        this.a = 17;
        Intrinsics.checkNotNullParameter(practiceTestsRepository, "practiceTestsRepository");
        Intrinsics.checkNotNullParameter(userInfoCache, "userInfoCache");
        this.b = practiceTestsRepository;
        this.c = userInfoCache;
    }

    public a(com.quizlet.local.ormlite.models.bookmark.a userLocalDataStore, com.quizlet.data.repository.course.membership.c userRemoteDataStore) {
        this.a = 19;
        Intrinsics.checkNotNullParameter(userLocalDataStore, "userLocalDataStore");
        Intrinsics.checkNotNullParameter(userRemoteDataStore, "userRemoteDataStore");
        this.b = userLocalDataStore;
        this.c = userRemoteDataStore;
    }

    public a(n dataSource, com.quizlet.quizletandroid.ui.joincontenttofolder.j mapper) {
        this.a = 29;
        Intrinsics.checkNotNullParameter(dataSource, "dataSource");
        Intrinsics.checkNotNullParameter(mapper, "mapper");
        this.b = dataSource;
        this.c = mapper;
    }

    public a(Context context, EventLogger eventLogger) {
        this.a = 26;
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(eventLogger, "eventLogger");
        this.b = context;
        this.c = eventLogger;
    }

    public a(Context context, FolderLogger folderLogger) throws Resources.NotFoundException {
        this.a = 20;
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(folderLogger, "folderLogger");
        this.b = folderLogger;
        String string = context.getResources().getString(R.string.folder_all);
        Intrinsics.checkNotNullExpressionValue(string, "getString(...)");
        this.c = string;
    }

    public a(C1721Kc remoteDataStore, org.slf4j.b logger) {
        this.a = 0;
        Intrinsics.checkNotNullParameter(remoteDataStore, "remoteDataStore");
        Intrinsics.checkNotNullParameter(logger, "logger");
        this.b = remoteDataStore;
        this.c = logger;
    }

    public a(com.quizlet.data.repository.folder.i repository, AbstractC5040y ioDispatcher) {
        this.a = 16;
        Intrinsics.checkNotNullParameter(repository, "repository");
        Intrinsics.checkNotNullParameter(ioDispatcher, "ioDispatcher");
        this.b = repository;
        this.c = ioDispatcher;
    }

    public a(Function0 onManageSubscriptionClick, Function0 onUpgradeNowClick) {
        this.a = 21;
        Intrinsics.checkNotNullParameter(onManageSubscriptionClick, "onManageSubscriptionClick");
        Intrinsics.checkNotNullParameter(onUpgradeNowClick, "onUpgradeNowClick");
        this.b = onManageSubscriptionClick;
        this.c = onUpgradeNowClick;
    }

    public a(int i) {
        this.a = i;
        switch (i) {
            case 7:
                this.b = new HashMap();
                this.c = new com.airbnb.lottie.network.d(19);
                break;
            case 8:
            case 10:
            case 11:
            default:
                s0 s0VarC = e0.c(new Pair(Integer.MIN_VALUE, null));
                this.b = s0VarC;
                this.c = new C1329n(s0VarC, 0);
                break;
            case 9:
                this.b = Collections.synchronizedMap(new WeakHashMap());
                this.c = Collections.synchronizedMap(new WeakHashMap());
                break;
            case 12:
                this.b = new AtomicInteger();
                this.c = new AtomicInteger();
                break;
            case 13:
                com.google.firebase.crashlytics.internal.common.j jVar = new com.google.firebase.crashlytics.internal.common.j();
                this.b = jVar;
                this.c = new com.google.firebase.messaging.p(jVar, 2);
                break;
        }
    }

    public a(a repository, androidx.work.impl.model.c dispatcher) {
        this.a = 15;
        Intrinsics.checkNotNullParameter(repository, "repository");
        Intrinsics.checkNotNullParameter(dispatcher, "dispatcher");
        this.b = repository;
        this.c = dispatcher;
    }

    public a(D d) {
        this.a = 1;
        this.b = d;
        Y y = new Y();
        this.c = y;
        y.j(new C0152d(5, null));
    }

    public a(WriteModeCheckPointView writeModeCheckPointView, com.onetrust.otpublishers.headless.databinding.b bVar) {
        this.a = 28;
        this.c = writeModeCheckPointView;
        this.b = bVar;
        ((QButton) bVar.c).setOnClickListener(new com.quizlet.quizletandroid.ui.common.adapter.viewholder.h(this, 20));
    }
}
