package com.quizlet.data.repository.folderset;

import android.animation.ValueAnimator;
import android.hardware.camera2.params.StreamConfigurationMap;
import android.os.Build;
import android.util.Size;
import android.view.Choreographer;
import androidx.appcompat.app.L;
import androidx.appcompat.widget.C0076c;
import androidx.camera.camera2.internal.compat.quirk.ExcludedSupportedSizesQuirk;
import androidx.camera.camera2.internal.compat.quirk.ExtraSupportedOutputSizeQuirk;
import androidx.compose.animation.core.O0;
import androidx.compose.runtime.internal.j;
import androidx.compose.ui.graphics.InterfaceC0858s;
import androidx.recyclerview.widget.C1372j;
import assistantMode.enums.k;
import assistantMode.tasks.sequencing.d;
import assistantMode.types.C1459f;
import assistantMode.types.q;
import assistantMode.types.w;
import com.facebook.z;
import com.google.android.datatransport.cct.internal.s;
import com.google.android.gms.internal.measurement.AbstractC3053s1;
import com.google.android.gms.internal.mlkit_vision_barcode.T;
import com.google.android.gms.internal.mlkit_vision_barcode.W4;
import com.google.android.gms.tasks.OnCompleteListener;
import com.google.android.gms.tasks.Task;
import com.quizlet.data.exceptions.user.LoggedInRequiredException;
import com.quizlet.data.model.B0;
import com.quizlet.data.model.Chapter;
import com.quizlet.data.model.ExerciseGroup;
import com.quizlet.data.model.InterfaceC4176w0;
import com.quizlet.data.model.Section;
import com.quizlet.data.model.TableOfContentItem;
import com.quizlet.db.data.caches.UserInfoCache;
import com.quizlet.features.infra.models.studymodeshared.StudyableModelData;
import com.quizlet.features.match.data.C4354j;
import com.quizlet.features.match.data.H;
import com.quizlet.features.match.settings.MatchSettingsData;
import com.quizlet.generated.enums.E1;
import com.quizlet.generated.enums.I0;
import com.quizlet.generated.enums.P;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.ui.common.ads.C4636c;
import com.quizlet.qutils.string.f;
import com.quizlet.remote.model.explanations.toc.RemoteChapter;
import com.quizlet.remote.model.explanations.toc.RemoteExerciseGroup;
import com.quizlet.remote.model.explanations.toc.RemoteSection;
import com.quizlet.remote.service.G;
import com.quizlet.utm.a;
import io.reactivex.rxjava3.core.g;
import io.reactivex.rxjava3.core.p;
import io.reactivex.rxjava3.functions.h;
import io.reactivex.rxjava3.internal.operators.observable.J;
import java.io.File;
import java.lang.reflect.Type;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import kotlin.Pair;
import kotlin.Unit;
import kotlin.collections.B;
import kotlin.collections.C4931w;
import kotlin.collections.C4933y;
import kotlin.collections.CollectionsKt;
import kotlin.collections.K;
import kotlin.jvm.internal.Intrinsics;
import kotlin.l;
import kotlin.sequences.Sequence;
import kotlin.text.CharsKt;
import kotlinx.coroutines.AbstractC5040y;
import kotlinx.coroutines.E;
import org.jsoup.nodes.i;
import org.jsoup.parser.C;
import org.jsoup.select.m;
import org.jsoup.select.n;
import retrofit2.InterfaceC5181f;
import retrofit2.adapter.rxjava3.e;
import retrofit2.u;

/* loaded from: classes2.dex */
public final class c implements d, OnCompleteListener, com.quizlet.data.repository.metering.a, h, com.quizlet.remote.mapper.base.b, InterfaceC5181f, n {
    public final /* synthetic */ int a;
    public Object b;
    public Object c;
    public Object d;

    public /* synthetic */ c(int i, boolean z) {
        this.a = i;
    }

    @Override // com.quizlet.data.repository.metering.a
    public Object a(long j, Long l, P p, kotlin.coroutines.jvm.internal.c cVar) {
        return E.J((AbstractC5040y) this.d, new com.quizlet.local.datastore.models.metering.a(this, j, l, p, null), cVar);
    }

    @Override // io.reactivex.rxjava3.functions.h
    public Object apply(Object obj) {
        f fVar;
        switch (this.a) {
            case 14:
                Intrinsics.checkNotNullParameter((Unit) obj, "<unused var>");
                return ((s) this.b).g((com.quizlet.qutils.data.offline.d) this.c, (String) this.d);
            case 15:
                File it2 = (File) obj;
                Intrinsics.checkNotNullParameter(it2, "it");
                return com.quizlet.quizletandroid.ui.common.images.loading.offline.c.c((com.quizlet.quizletandroid.ui.common.images.loading.offline.c) this.b, (String) this.c, it2, (com.quizlet.quizletandroid.data.cache.a) this.d);
            default:
                Pair pair = (Pair) obj;
                Intrinsics.checkNotNullParameter(pair, "<destruct>");
                com.quizlet.features.infra.basestudy.data.models.shareset.a aVar = (com.quizlet.features.infra.basestudy.data.models.shareset.a) pair.a;
                Object obj2 = pair.b;
                Intrinsics.checkNotNullExpressionValue(obj2, "component2(...)");
                long jLongValue = ((Long) obj2).longValue();
                com.quizlet.quizletandroid.ui.studymodes.match.managers.a aVar2 = (com.quizlet.quizletandroid.ui.studymodes.match.managers.a) this.b;
                aVar2.getClass();
                okhttp3.s sVarD = null;
                Double dValueOf = jLongValue < 0 ? null : Double.valueOf(jLongValue / 10.0d);
                String url = (String) this.c;
                String str = (String) this.d;
                if (dValueOf == null) {
                    Object[] args = {str, url};
                    Intrinsics.checkNotNullParameter(args, "args");
                    fVar = new f(R.string.share_message, C4933y.P(args));
                } else {
                    double dDoubleValue = dValueOf.doubleValue();
                    Intrinsics.checkNotNullParameter(url, "url");
                    okhttp3.s sVarC = com.quizlet.quizletandroid.deeplinks.a.c(url);
                    if (sVarC != null) {
                        C1372j c1372jF = sVarC.f();
                        String string = Long.toString(((int) (dDoubleValue * 10)) * 199, CharsKt.checkRadix(36));
                        Intrinsics.checkNotNullExpressionValue(string, "toString(...)");
                        c1372jF.c("sc", string);
                        sVarD = c1372jF.d();
                    }
                    Object[] args2 = {str, dValueOf, String.valueOf(sVarD)};
                    Intrinsics.checkNotNullParameter(args2, "args");
                    fVar = new f(R.string.share_message_match, C4933y.P(args2));
                }
                return new C4354j(new H(aVar, aVar2.a.u, url, str, new a.C0023a(new a.c(com.quizlet.utm.campaigns.b.MATCH_COMPLETE_SHARE, com.quizlet.utm.mediums.b.SHARE_LINK, com.quizlet.utm.sources.b.SHARE_SHEET_ANDROID), Long.valueOf(aVar2.b.e.getPersonId())), fVar));
        }
    }

    @Override // retrofit2.InterfaceC5181f
    public Type b() {
        Type type = ((e) this.c).a;
        Intrinsics.checkNotNullExpressionValue(type, "responseType(...)");
        return type;
    }

    @Override // org.jsoup.select.n
    public void d(org.jsoup.nodes.n nVar, int i) {
        if (nVar instanceof i) {
            i iVar = (i) nVar;
            if (((m) this.d).a((i) this.b, iVar)) {
                ((C) this.c).add(iVar);
            }
        }
    }

    @Override // com.quizlet.remote.mapper.base.a
    public List e(List list) {
        return T.f(this, list);
    }

    @Override // assistantMode.tasks.sequencing.d
    public void f(List completedStudiableItemTuples) {
        Intrinsics.checkNotNullParameter(completedStudiableItemTuples, "completedStudiableItemTuples");
        O0 o0 = (O0) this.d;
        o0.getClass();
        Intrinsics.checkNotNullParameter(completedStudiableItemTuples, "completedStudiableItemTuples");
        o0.a.removeAll(completedStudiableItemTuples);
    }

    /* JADX WARN: Type inference failed for: r7v1, types: [java.lang.Object, kotlin.k] */
    @Override // assistantMode.tasks.sequencing.d
    public w g() {
        C4931w c4931wD = CollectionsKt.D(((O0) this.d).a);
        assistantMode.tasks.sequencing.a selector = assistantMode.tasks.sequencing.a.a;
        Intrinsics.checkNotNullParameter(c4931wD, "<this>");
        Intrinsics.checkNotNullParameter(selector, "selector");
        Sequence c4931w = new C4931w(c4931wD);
        Intrinsics.checkNotNullParameter(c4931w, "<this>");
        List<q> listJ = kotlin.sequences.q.j(c4931w instanceof kotlin.sequences.c ? ((kotlin.sequences.c) c4931w).take() : new kotlin.sequences.s(c4931w));
        ArrayList arrayList = new ArrayList(kotlin.collections.C.q(listJ, 10));
        Iterator it2 = listJ.iterator();
        while (it2.hasNext()) {
            arrayList.add(((q) it2.next()).b);
        }
        ArrayList arrayList2 = new ArrayList(kotlin.collections.C.q(listJ, 10));
        for (q qVar : listJ) {
            long j = qVar.a;
            j jVar = (j) this.b;
            List listN = B.n(jVar.h(j, W4.d(qVar.b, jVar.i(j), true)), (kotlin.random.e) this.c.getValue());
            ArrayList arrayList3 = new ArrayList();
            Iterator it3 = ((ArrayList) listN).iterator();
            while (it3.hasNext()) {
                Object next = it3.next();
                C1459f questionSpec = (C1459f) next;
                Intrinsics.checkNotNullParameter(questionSpec, "questionSpec");
                if (jVar.j(questionSpec.a, questionSpec.b, questionSpec.c).contains(questionSpec.d)) {
                    arrayList3.add(next);
                }
            }
            C1459f c1459f = (C1459f) CollectionsKt.firstOrNull(CollectionsKt.n0(CollectionsKt.A0(arrayList3), new androidx.camera.core.streamsharing.a(jVar, 6)));
            if (c1459f == null) {
                c1459f = new C1459f(j, assistantMode.enums.m.b, assistantMode.enums.m.c, k.f);
            }
            arrayList2.add(c1459f);
        }
        return new w(arrayList, arrayList2);
    }

    @Override // org.jsoup.select.n
    public void i(org.jsoup.nodes.n nVar, int i) {
    }

    @Override // retrofit2.InterfaceC5181f
    public Object j(u call) {
        Intrinsics.checkNotNullParameter(call, "call");
        Object objJ = ((e) this.c).j(call);
        boolean z = objJ instanceof io.reactivex.rxjava3.core.i;
        G g = (G) this.d;
        if (z) {
            return new J((io.reactivex.rxjava3.core.i) objJ, new androidx.compose.foundation.text.input.internal.u(g, false, this, 29), 4);
        }
        if (objJ instanceof g) {
            return new io.reactivex.rxjava3.internal.operators.maybe.s((g) objJ, new com.quizlet.remote.model.progress.e(g, this), 1);
        }
        if (objJ instanceof p) {
            return new io.reactivex.rxjava3.internal.operators.single.g((p) objJ, new com.quizlet.remote.model.report.c(g, this), 2);
        }
        if (objJ instanceof io.reactivex.rxjava3.core.e) {
            return new io.reactivex.rxjava3.internal.operators.flowable.f((io.reactivex.rxjava3.core.e) objJ, new com.quizlet.remote.model.school.h(g, this));
        }
        if (!(objJ instanceof io.reactivex.rxjava3.core.a)) {
            return objJ;
        }
        return new io.reactivex.rxjava3.internal.operators.completable.a(2, (io.reactivex.rxjava3.core.a) objJ, new com.quizlet.remote.model.search.d(g, this));
    }

    public void k() {
        com.iab.omid.library.amazon.walking.async.a aVar = (com.iab.omid.library.amazon.walking.async.a) ((ArrayDeque) this.c).poll();
        this.d = aVar;
        if (aVar != null) {
            aVar.executeOnExecutor((ThreadPoolExecutor) this.b, new Object[0]);
        }
    }

    public void l(int[] iArr, ValueAnimator valueAnimator) {
        assistantMode.utils.studiableMetadata.b bVar = new assistantMode.utils.studiableMetadata.b(iArr, valueAnimator);
        valueAnimator.addListener((C0076c) this.d);
        ((ArrayList) this.b).add(bVar);
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object m(kotlin.coroutines.h r6) {
        /*
            r5 = this;
            boolean r0 = r6 instanceof com.quizlet.featuregate.features.games.a
            if (r0 == 0) goto L13
            r0 = r6
            com.quizlet.featuregate.features.games.a r0 = (com.quizlet.featuregate.features.games.a) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            com.quizlet.featuregate.features.games.a r0 = new com.quizlet.featuregate.features.games.a
            r0.<init>(r5, r6)
        L18:
            java.lang.Object r6 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 2
            r4 = 1
            if (r2 == 0) goto L38
            if (r2 == r4) goto L32
            if (r2 != r3) goto L2a
            androidx.glance.appwidget.protobuf.Z.e(r6)
            return r6
        L2a:
            java.lang.IllegalStateException r6 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r6.<init>(r0)
            throw r6
        L32:
            com.quizlet.data.repository.folderset.c r2 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r6)
            goto L4f
        L38:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            java.lang.Object r6 = r5.b
            androidx.work.impl.model.c r6 = (androidx.work.impl.model.c) r6
            io.reactivex.rxjava3.internal.operators.single.g r6 = r6.r()
            r0.j = r5
            r0.m = r4
            java.lang.Object r6 = com.google.android.gms.internal.mlkit_vision_camera.I1.b(r6, r0)
            if (r6 != r1) goto L4e
            goto L6a
        L4e:
            r2 = r5
        L4f:
            java.lang.Boolean r6 = (java.lang.Boolean) r6
            boolean r6 = r6.booleanValue()
            if (r6 != 0) goto L6c
            java.lang.Object r6 = r2.c
            com.quizlet.data.repository.activitycenter.b r6 = (com.quizlet.data.repository.activitycenter.b) r6
            r4 = 0
            r0.j = r4
            r0.m = r3
            java.lang.Object r2 = r2.d
            com.quizlet.generated.enums.I0 r2 = (com.quizlet.generated.enums.I0) r2
            java.lang.Object r6 = r6.j(r2, r0)
            if (r6 != r1) goto L6b
        L6a:
            return r1
        L6b:
            return r6
        L6c:
            java.lang.Boolean r6 = java.lang.Boolean.FALSE
            return r6
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.repository.folderset.c.m(kotlin.coroutines.h):java.lang.Object");
    }

    public J n(io.reactivex.rxjava3.internal.operators.single.g gVar) {
        J j = new J(new com.jakewharton.rxbinding4.a(new com.quizlet.data.repository.classfolder.b(4, this, gVar), 4), new com.quizlet.data.interactor.course.a(this, 6), 4);
        Intrinsics.checkNotNullExpressionValue(j, "onErrorResumeNext(...)");
        J jQ = j.q(b.b);
        Intrinsics.checkNotNullExpressionValue(jQ, "map(...)");
        return jQ;
    }

    public InterfaceC0858s o() {
        return ((androidx.compose.ui.graphics.drawscope.b) this.d).a.c;
    }

    @Override // com.google.android.gms.tasks.OnCompleteListener
    public void onComplete(Task task) {
        com.google.android.gms.cloudmessaging.a aVar = (com.google.android.gms.cloudmessaging.a) this.b;
        String str = (String) this.c;
        ScheduledFuture scheduledFuture = (ScheduledFuture) this.d;
        synchronized (aVar.a) {
            aVar.a.remove(str);
        }
        scheduledFuture.cancel(false);
    }

    public Size[] p(int i) {
        List arrayList;
        ArrayList arrayList2;
        HashMap map = (HashMap) this.d;
        if (map.containsKey(Integer.valueOf(i))) {
            if (((Size[]) map.get(Integer.valueOf(i))) == null) {
                return null;
            }
            return (Size[]) ((Size[]) map.get(Integer.valueOf(i))).clone();
        }
        Size[] outputSizes = ((StreamConfigurationMap) ((com.google.android.gms.internal.instantapps.a) this.b).b).getOutputSizes(i);
        if (outputSizes == null || outputSizes.length == 0) {
            AbstractC3053s1.h("StreamConfigurationMapCompat", "Retrieved output sizes array is null or empty for format " + i);
            return outputSizes;
        }
        androidx.work.impl.model.c cVar = (androidx.work.impl.model.c) this.c;
        cVar.getClass();
        ArrayList arrayList3 = new ArrayList(Arrays.asList(outputSizes));
        if (((ExtraSupportedOutputSizeQuirk) cVar.b) != null) {
            Size[] sizeArr = (i == 34 && "motorola".equalsIgnoreCase(Build.BRAND) && "moto e5 play".equalsIgnoreCase(Build.MODEL)) ? new Size[]{new Size(1440, 1080), new Size(960, 720)} : new Size[0];
            if (sizeArr.length > 0) {
                arrayList3.addAll(Arrays.asList(sizeArr));
            }
        }
        androidx.camera.camera2.internal.compat.workaround.b bVar = (androidx.camera.camera2.internal.compat.workaround.b) cVar.c;
        bVar.getClass();
        if (((ExcludedSupportedSizesQuirk) androidx.camera.camera2.internal.compat.quirk.b.a.b(ExcludedSupportedSizesQuirk.class)) == null) {
            arrayList = new ArrayList();
        } else {
            String str = bVar.b;
            String str2 = Build.BRAND;
            if ("OnePlus".equalsIgnoreCase(str2) && "OnePlus6".equalsIgnoreCase(Build.DEVICE)) {
                arrayList2 = new ArrayList();
                if (str.equals("0") && i == 256) {
                    arrayList2.add(new Size(4160, 3120));
                    arrayList2.add(new Size(4000, 3000));
                }
            } else if ("OnePlus".equalsIgnoreCase(str2) && "OnePlus6T".equalsIgnoreCase(Build.DEVICE)) {
                arrayList2 = new ArrayList();
                if (str.equals("0") && i == 256) {
                    arrayList2.add(new Size(4160, 3120));
                    arrayList2.add(new Size(4000, 3000));
                }
            } else {
                if ("HUAWEI".equalsIgnoreCase(str2) && "HWANE".equalsIgnoreCase(Build.DEVICE)) {
                    arrayList2 = new ArrayList();
                    if (str.equals("0") && (i == 34 || i == 35)) {
                        arrayList2.add(new Size(720, 720));
                        arrayList2.add(new Size(400, 400));
                    }
                } else if (ExcludedSupportedSizesQuirk.c()) {
                    arrayList2 = new ArrayList();
                    if (str.equals("0")) {
                        if (i == 34) {
                            arrayList2.add(new Size(4128, 3096));
                            arrayList2.add(new Size(4128, 2322));
                            arrayList2.add(new Size(3088, 3088));
                            arrayList2.add(new Size(3264, 2448));
                            arrayList2.add(new Size(3264, 1836));
                            arrayList2.add(new Size(2048, 1536));
                            arrayList2.add(new Size(2048, 1152));
                            arrayList2.add(new Size(1920, 1080));
                        } else if (i == 35) {
                            arrayList2.add(new Size(4128, 2322));
                            arrayList2.add(new Size(3088, 3088));
                            arrayList2.add(new Size(3264, 2448));
                            arrayList2.add(new Size(3264, 1836));
                            arrayList2.add(new Size(2048, 1536));
                            arrayList2.add(new Size(2048, 1152));
                            arrayList2.add(new Size(1920, 1080));
                        }
                    } else if (str.equals("1") && (i == 34 || i == 35)) {
                        arrayList2.add(new Size(3264, 2448));
                        arrayList2.add(new Size(3264, 1836));
                        arrayList2.add(new Size(2448, 2448));
                        arrayList2.add(new Size(1920, 1920));
                        arrayList2.add(new Size(2048, 1536));
                        arrayList2.add(new Size(2048, 1152));
                        arrayList2.add(new Size(1920, 1080));
                    }
                } else if (ExcludedSupportedSizesQuirk.b()) {
                    arrayList2 = new ArrayList();
                    if (str.equals("0")) {
                        if (i == 34) {
                            arrayList2.add(new Size(4128, 3096));
                            arrayList2.add(new Size(4128, 2322));
                            arrayList2.add(new Size(3088, 3088));
                            arrayList2.add(new Size(3264, 2448));
                            arrayList2.add(new Size(3264, 1836));
                            arrayList2.add(new Size(2048, 1536));
                            arrayList2.add(new Size(2048, 1152));
                            arrayList2.add(new Size(1920, 1080));
                        } else if (i == 35) {
                            arrayList2.add(new Size(2048, 1536));
                            arrayList2.add(new Size(2048, 1152));
                            arrayList2.add(new Size(1920, 1080));
                        }
                    } else if (str.equals("1") && (i == 34 || i == 35)) {
                        arrayList2.add(new Size(2576, 1932));
                        arrayList2.add(new Size(2560, 1440));
                        arrayList2.add(new Size(1920, 1920));
                        arrayList2.add(new Size(2048, 1536));
                        arrayList2.add(new Size(2048, 1152));
                        arrayList2.add(new Size(1920, 1080));
                    }
                } else if ("REDMI".equalsIgnoreCase(str2) && "joyeuse".equalsIgnoreCase(Build.DEVICE)) {
                    arrayList2 = new ArrayList();
                    if (str.equals("0") && i == 256) {
                        arrayList2.add(new Size(9280, 6944));
                    }
                } else {
                    AbstractC3053s1.h("ExcludedSupportedSizesQuirk", "Cannot retrieve list of supported sizes to exclude on this device.");
                    arrayList = Collections.EMPTY_LIST;
                }
            }
            arrayList = arrayList2;
        }
        if (!arrayList.isEmpty()) {
            arrayList3.removeAll(arrayList);
        }
        if (arrayList3.isEmpty()) {
            AbstractC3053s1.h("OutputSizesCorrector", "Sizes array becomes empty after excluding problematic output sizes.");
        }
        Size[] sizeArr2 = (Size[]) arrayList3.toArray(new Size[0]);
        map.put(Integer.valueOf(i), sizeArr2);
        return (Size[]) sizeArr2.clone();
    }

    public MatchSettingsData q() {
        com.quizlet.features.infra.studysetting.managers.a aVar = (com.quizlet.features.infra.studysetting.managers.a) this.d;
        if (aVar == null) {
            throw new IllegalStateException("Must set StudySettingManger before calling any other method");
        }
        if (aVar == null) {
            Intrinsics.m("studySettingManager");
            throw null;
        }
        E1 e1 = E1.MATCH_MODE_SIDES;
        Set set = com.quizlet.features.infra.studysetting.managers.a.h;
        long jE = aVar.e(e1, null);
        boolean z = (2 & jE) >= 1;
        boolean z2 = (4 & jE) >= 1;
        boolean z3 = (jE & 16) >= 1;
        StudyableModelData studyableModelData = (StudyableModelData) this.c;
        return new MatchSettingsData(((z) this.b).a(studyableModelData.k(), studyableModelData.getStudyableType()), z, z2, z3);
    }

    public long r() {
        return ((androidx.compose.ui.graphics.drawscope.b) this.d).a.d;
    }

    @Override // com.quizlet.remote.mapper.base.a
    /* renamed from: s, reason: merged with bridge method [inline-methods] */
    public TableOfContentItem c(com.quizlet.remote.model.explanations.toc.a remote) {
        Intrinsics.checkNotNullParameter(remote, "remote");
        if (remote instanceof RemoteChapter) {
            RemoteChapter remote2 = (RemoteChapter) remote;
            com.quizlet.quizletandroid.ui.activitycenter.views.i iVar = (com.quizlet.quizletandroid.ui.activitycenter.views.i) this.b;
            Intrinsics.checkNotNullParameter(remote2, "remote");
            Intrinsics.checkNotNullParameter(this, "remoteTableOfContentItemMapper");
            long j = remote2.a;
            List list = remote2.e;
            if (list == null) {
                list = K.a;
            }
            ArrayList arrayListF = T.f(this, list);
            List list2 = remote2.f;
            if (list2 == null) {
                list2 = K.a;
            }
            ArrayList arrayListF2 = T.f((com.quizlet.quizletandroid.ui.common.images.capture.b) iVar.b, list2);
            return new Chapter(j, remote2.b, remote2.c, remote2.d, arrayListF, arrayListF2);
        }
        if (!(remote instanceof RemoteSection)) {
            if (remote instanceof RemoteExerciseGroup) {
                return ((com.quizlet.local.ormlite.models.term.b) this.d).c((RemoteExerciseGroup) remote);
            }
            throw new IllegalStateException(android.support.v4.media.session.a.B("Not a valid remote type (", remote.getClass().getSimpleName(), ")"));
        }
        RemoteSection remote3 = (RemoteSection) remote;
        C4636c c4636c = (C4636c) this.c;
        Intrinsics.checkNotNullParameter(remote3, "remote");
        Intrinsics.checkNotNullParameter(this, "remoteTableOfContentItemMapper");
        long j2 = remote3.a;
        List list3 = remote3.e;
        if (list3 == null) {
            list3 = K.a;
        }
        ArrayList arrayListF3 = T.f(this, list3);
        List list4 = remote3.f;
        if (list4 == null) {
            list4 = K.a;
        }
        ArrayList arrayListF4 = T.f((com.quizlet.quizletandroid.ui.common.images.capture.b) c4636c.b, list4);
        return new Section(j2, remote3.b, remote3.c, remote3.d, arrayListF3, arrayListF4);
    }

    @Override // com.quizlet.remote.mapper.base.c
    /* renamed from: t, reason: merged with bridge method [inline-methods] */
    public com.quizlet.remote.model.explanations.toc.a h(TableOfContentItem data) {
        Intrinsics.checkNotNullParameter(data, "data");
        if (data instanceof Chapter) {
            Chapter data2 = (Chapter) data;
            com.quizlet.quizletandroid.ui.activitycenter.views.i iVar = (com.quizlet.quizletandroid.ui.activitycenter.views.i) this.b;
            Intrinsics.checkNotNullParameter(data2, "data");
            Intrinsics.checkNotNullParameter(this, "remoteTableOfContentItemMapper");
            long j = data2.a;
            ArrayList arrayListG = T.g(this, data2.e);
            ArrayList arrayListG2 = T.g((com.quizlet.quizletandroid.ui.common.images.capture.b) iVar.b, data2.f);
            return new RemoteChapter(j, data2.c, data2.d, data2.b, arrayListG, arrayListG2);
        }
        if (!(data instanceof Section)) {
            if (data instanceof ExerciseGroup) {
                return ((com.quizlet.local.ormlite.models.term.b) this.d).h((ExerciseGroup) data);
            }
            throw new IllegalStateException(android.support.v4.media.session.a.B("Not a valid data type (", data.getClass().getSimpleName(), ")"));
        }
        Section data3 = (Section) data;
        C4636c c4636c = (C4636c) this.c;
        Intrinsics.checkNotNullParameter(data3, "data");
        Intrinsics.checkNotNullParameter(this, "remoteTableOfContentItemMapper");
        long j2 = data3.a;
        ArrayList arrayListG3 = T.g(this, data3.e);
        ArrayList arrayListG4 = T.g((com.quizlet.quizletandroid.ui.common.images.capture.b) c4636c.b, data3.f);
        return new RemoteSection(j2, data3.c, data3.d, data3.b, arrayListG3, arrayListG4);
    }

    public io.reactivex.rxjava3.core.a u(long j, B0 item, p stopToken) {
        Intrinsics.checkNotNullParameter(item, "item");
        Intrinsics.checkNotNullParameter(stopToken, "stopToken");
        if (!((UserInfoCache) this.d).b()) {
            return new io.reactivex.rxjava3.internal.operators.completable.c(new LoggedInRequiredException(), 3);
        }
        return ((androidx.work.impl.model.c) this.c).a(stopToken, new com.braze.H(this, j, item, 6));
    }

    public void v(InterfaceC0858s interfaceC0858s) {
        ((androidx.compose.ui.graphics.drawscope.b) this.d).a.c = interfaceC0858s;
    }

    public void w(androidx.compose.ui.unit.b bVar) {
        ((androidx.compose.ui.graphics.drawscope.b) this.d).a.a = bVar;
    }

    public void x(androidx.compose.ui.unit.k kVar) {
        ((androidx.compose.ui.graphics.drawscope.b) this.d).a.b = kVar;
    }

    public void y(long j) {
        ((androidx.compose.ui.graphics.drawscope.b) this.d).a.d = j;
    }

    public Object z(InterfaceC4176w0 interfaceC4176w0, kotlin.coroutines.jvm.internal.c cVar) {
        return E.J((AbstractC5040y) this.d, new com.quizlet.local.datastore.models.metering.b(this, interfaceC4176w0, null), cVar);
    }

    public /* synthetic */ c(Object obj, Object obj2, Object obj3, int i) {
        this.a = i;
        this.b = obj;
        this.c = obj2;
        this.d = obj3;
    }

    public c(com.quizlet.quizletandroid.ui.activitycenter.views.i remoteChapterMapper, C4636c remoteSectionMapper, com.quizlet.local.ormlite.models.term.b remoteExerciseGroupMapper) {
        this.a = 17;
        Intrinsics.checkNotNullParameter(remoteChapterMapper, "remoteChapterMapper");
        Intrinsics.checkNotNullParameter(remoteSectionMapper, "remoteSectionMapper");
        Intrinsics.checkNotNullParameter(remoteExerciseGroupMapper, "remoteExerciseGroupMapper");
        this.b = remoteChapterMapper;
        this.c = remoteSectionMapper;
        this.d = remoteExerciseGroupMapper;
    }

    public c(com.quizlet.local.datastore.models.metering.i manager, com.quizlet.local.datastore.models.metering.j mapper, AbstractC5040y dispatcher) {
        this.a = 13;
        Intrinsics.checkNotNullParameter(manager, "manager");
        Intrinsics.checkNotNullParameter(mapper, "mapper");
        Intrinsics.checkNotNullParameter(dispatcher, "dispatcher");
        this.b = manager;
        this.c = mapper;
        this.d = dispatcher;
    }

    public c(androidx.work.impl.model.c userProps, com.quizlet.data.repository.activitycenter.b eligibilityFeature, I0 productFeature) {
        this.a = 11;
        Intrinsics.checkNotNullParameter(userProps, "userProps");
        Intrinsics.checkNotNullParameter(eligibilityFeature, "eligibilityFeature");
        Intrinsics.checkNotNullParameter(productFeature, "productFeature");
        this.b = userProps;
        this.c = eligibilityFeature;
        this.d = productFeature;
    }

    public c(assistantMode.refactored.types.Task currentTask, ArrayList originalOrderCardIds, j questionTypeApplicability, boolean z) {
        this.a = 4;
        Intrinsics.checkNotNullParameter(currentTask, "currentTask");
        Intrinsics.checkNotNullParameter(originalOrderCardIds, "originalOrderCardIds");
        Intrinsics.checkNotNullParameter(questionTypeApplicability, "questionTypeApplicability");
        this.b = questionTypeApplicability;
        kotlin.k kVarA = l.a(kotlin.m.a, new assistantMode.tasks.sequencing.f(0));
        this.c = kVarA;
        this.d = new O0(CollectionsKt.A0(z ? B.n(originalOrderCardIds, (kotlin.random.e) kVarA.getValue()) : originalOrderCardIds), currentTask.a);
    }

    public c(z setInSelectedTermsModeCache, StudyableModelData studyableModelData) {
        this.a = 12;
        Intrinsics.checkNotNullParameter(setInSelectedTermsModeCache, "setInSelectedTermsModeCache");
        Intrinsics.checkNotNullParameter(studyableModelData, "studyableModelData");
        this.b = setInSelectedTermsModeCache;
        this.c = studyableModelData;
    }

    public c(com.onetrust.otpublishers.headless.UI.fragment.q factory, com.quizlet.data.connectivity.a networkStatus, org.slf4j.b logger) {
        this.a = 0;
        com.quizlet.time.b timeProvider = com.quizlet.time.b.a;
        Intrinsics.checkNotNullParameter(factory, "factory");
        Intrinsics.checkNotNullParameter(networkStatus, "networkStatus");
        Intrinsics.checkNotNullParameter(logger, "logger");
        Intrinsics.checkNotNullParameter(timeProvider, "timeProvider");
        this.b = factory;
        this.c = networkStatus;
        this.d = logger;
    }

    public c(com.quizlet.data.repository.explanations.myexplanations.a repository, androidx.work.impl.model.c dispatcher, UserInfoCache userInfoCache) {
        this.a = 10;
        Intrinsics.checkNotNullParameter(repository, "repository");
        Intrinsics.checkNotNullParameter(dispatcher, "dispatcher");
        Intrinsics.checkNotNullParameter(userInfoCache, "userInfoCache");
        this.b = repository;
        this.c = dispatcher;
        this.d = userInfoCache;
    }

    public c(int i) {
        this.a = i;
        switch (i) {
            case 9:
                this.c = new ArrayDeque();
                this.d = null;
                this.b = new ThreadPoolExecutor(1, 1, 1L, TimeUnit.SECONDS, new LinkedBlockingQueue());
                break;
            default:
                this.b = new ArrayList();
                this.c = null;
                this.d = new C0076c(this, 7);
                break;
        }
    }

    public c(StreamConfigurationMap streamConfigurationMap, androidx.work.impl.model.c cVar) {
        this.a = 1;
        this.d = new HashMap();
        new HashMap();
        new HashMap();
        this.b = new com.google.android.gms.internal.instantapps.a(streamConfigurationMap, 4);
        this.c = cVar;
    }

    public c(androidx.compose.ui.graphics.drawscope.b bVar) {
        this.a = 2;
        this.d = bVar;
        this.b = new L(this, 9);
    }

    public c(G g, retrofit2.L retrofit, e callAdapter) {
        this.a = 18;
        Intrinsics.checkNotNullParameter(retrofit, "retrofit");
        Intrinsics.checkNotNullParameter(callAdapter, "callAdapter");
        this.d = g;
        this.b = retrofit;
        this.c = callAdapter;
    }

    public c(com.google.android.gms.internal.instantapps.a aVar) {
        this.a = 3;
        this.a = 3;
        this.b = aVar;
        this.c = Choreographer.getInstance();
        this.d = new androidx.dynamicanimation.animation.a(this);
    }
}
