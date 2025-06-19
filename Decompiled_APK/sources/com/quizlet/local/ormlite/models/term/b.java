package com.quizlet.local.ormlite.models.term;

import android.graphics.Bitmap;
import android.net.Uri;
import android.provider.MediaStore;
import androidx.work.impl.model.e;
import com.google.android.datatransport.cct.internal.s;
import com.google.android.gms.internal.mlkit_vision_barcode.Q;
import com.google.android.gms.internal.mlkit_vision_barcode.S;
import com.google.android.gms.internal.mlkit_vision_barcode.T;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3771z;
import com.google.android.gms.measurement.internal.J;
import com.quizlet.data.model.A1;
import com.quizlet.data.model.C4112b1;
import com.quizlet.data.model.C4162r1;
import com.quizlet.data.model.ExerciseGroup;
import com.quizlet.data.model.School;
import com.quizlet.data.model.X0;
import com.quizlet.data.model.w2;
import com.quizlet.db.data.models.persisted.base.Models;
import com.quizlet.db.data.models.persisted.fields.DBSelectedTermFields;
import com.quizlet.eventlogger.EventLogger;
import com.quizlet.generated.enums.C4531x0;
import com.quizlet.generated.enums.EnumC4533y0;
import com.quizlet.generated.enums.w1;
import com.quizlet.local.ormlite.util.c;
import com.quizlet.quizletandroid.data.management.d;
import com.quizlet.quizletandroid.t;
import com.quizlet.quizletandroid.u;
import com.quizlet.quizletandroid.ui.common.dialogs.TextOverlayDialogFragment;
import com.quizlet.quizletandroid.ui.startpage.nav2.Y;
import com.quizlet.quizletandroid.ui.startpage.nav2.model.C4718n;
import com.quizlet.quizletandroid.ui.startpage.nav2.model.P;
import com.quizlet.quizletandroid.ui.startpage.nav2.model.z;
import com.quizlet.quizletandroid.ui.usersettings.fragments.CropImageFragment;
import com.quizlet.remote.model.base.ApiThreeWrapper;
import com.quizlet.remote.model.base.PagingInfo;
import com.quizlet.remote.model.course.RemoteCourse;
import com.quizlet.remote.model.explanations.toc.RemoteExerciseGroup;
import com.quizlet.remote.model.practicetests.PracticeTestsAnswerOptionResponse;
import com.quizlet.remote.model.practicetests.PracticeTestsImageDataResponse;
import com.quizlet.remote.model.practicetests.PracticeTestsQuestionResponse;
import com.quizlet.remote.model.school.RemoteSchool;
import com.quizlet.remote.model.set.RecommendedSetsSchoolCourseBasedResponse;
import com.quizlet.remote.model.user.RemoteUser;
import com.quizlet.remote.model.user.UserModels;
import com.quizlet.remote.model.user.UserResponse;
import io.reactivex.rxjava3.core.i;
import io.reactivex.rxjava3.core.p;
import io.reactivex.rxjava3.functions.g;
import io.reactivex.rxjava3.functions.h;
import java.io.IOException;
import java.lang.reflect.Type;
import java.net.Socket;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.TimeUnit;
import kotlin.collections.A;
import kotlin.collections.C;
import kotlin.collections.CollectionsKt;
import kotlin.collections.K;
import kotlin.jvm.internal.B;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.O;
import okhttp3.r;
import retrofit2.C5183h;
import retrofit2.InterfaceC5181f;

/* loaded from: classes3.dex */
public final /* synthetic */ class b implements h, dagger.android.b, com.quizlet.remote.mapper.base.b, com.quizlet.mapper.a, InterfaceC5181f {
    public final /* synthetic */ int a;
    public final Object b;

    public b(com.quizlet.quizletandroid.ui.activitycenter.models.a aVar, com.quizlet.quizletandroid.ui.folder.logging.a aVar2) {
        this.a = 18;
        this.b = aVar;
    }

    @Override // com.quizlet.mapper.a
    public Object a(Object obj) {
        PracticeTestsQuestionResponse input = (PracticeTestsQuestionResponse) obj;
        Intrinsics.checkNotNullParameter(input, "input");
        ArrayList arrayList = new ArrayList();
        Map map = input.f;
        com.quizlet.quizletandroid.logging.initializer.a aVar = (com.quizlet.quizletandroid.logging.initializer.a) this.b;
        if (map != null) {
            for (Map.Entry entry : map.entrySet()) {
                ArrayList arrayList2 = new ArrayList();
                List list = ((PracticeTestsAnswerOptionResponse) entry.getValue()).b;
                if (list != null) {
                    Iterator it2 = list.iterator();
                    while (it2.hasNext()) {
                        arrayList2.add(aVar.a((PracticeTestsImageDataResponse) it2.next()));
                    }
                }
                arrayList.add(new C4112b1(((PracticeTestsAnswerOptionResponse) entry.getValue()).a, arrayList2));
            }
        }
        ArrayList arrayList3 = new ArrayList();
        List list2 = input.i;
        if (list2 != null) {
            Iterator it3 = list2.iterator();
            while (it3.hasNext()) {
                arrayList3.add(aVar.a((PracticeTestsImageDataResponse) it3.next()));
            }
        }
        EnumC4533y0.Companion.getClass();
        EnumC4533y0 enumC4533y0A = C4531x0.a(input.g);
        return new X0(input.a, input.c, input.d, arrayList, enumC4533y0A, arrayList3);
    }

    @Override // io.reactivex.rxjava3.functions.h
    public Object apply(Object obj) throws IOException {
        List listF;
        PagingInfo pagingInfo;
        UserModels userModels;
        List list;
        A1 a1I = null;
        Object obj2 = this.b;
        switch (this.a) {
            case 0:
                List p0 = (List) obj;
                Intrinsics.checkNotNullParameter(p0, "p0");
                return AbstractC3771z.c((a) obj2, p0);
            case 1:
                List p02 = (List) obj;
                Intrinsics.checkNotNullParameter(p02, "p0");
                return ((c) obj2).g(p02);
            case 2:
            case 3:
            case 6:
            case 8:
            case 9:
            case 10:
            case 14:
            case 15:
            case 16:
            default:
                Object[] objArr = (Object[]) obj;
                if (objArr.length == 5) {
                    return ((g) obj2).e(objArr[0], objArr[1], objArr[2], objArr[3], objArr[4]);
                }
                throw new IllegalArgumentException("Array of size 5 expected but got " + objArr.length);
            case 4:
                List p03 = (List) obj;
                Intrinsics.checkNotNullParameter(p03, "p0");
                s sVar = (s) obj2;
                sVar.getClass();
                com.quizlet.quizletandroid.data.management.a aVar = (com.quizlet.quizletandroid.data.management.a) CollectionsKt.firstOrNull(p03);
                if (aVar == null) {
                    io.reactivex.rxjava3.internal.operators.flowable.b bVarF = p.f(p03);
                    Intrinsics.checkNotNullExpressionValue(bVarF, "just(...)");
                    return bVarF;
                }
                ArrayList arrayList = new ArrayList(C.q(p03, 10));
                Iterator it2 = p03.iterator();
                while (it2.hasNext()) {
                    arrayList.add(Long.valueOf(((com.quizlet.quizletandroid.data.management.a) it2.next()).a.getId()));
                }
                Set setA0 = CollectionsKt.A0(arrayList);
                com.quizlet.infra.legacysyncengine.orm.b bVar = new com.quizlet.infra.legacysyncengine.orm.b(Models.SELECTED_TERM);
                bVar.c(DBSelectedTermFields.SET, setA0, null);
                bVar.b(Long.valueOf(aVar.c), DBSelectedTermFields.PERSON);
                com.quizlet.infra.legacysyncengine.orm.query.a aVarA = bVar.a();
                Intrinsics.checkNotNullExpressionValue(aVarA, "build(...)");
                io.reactivex.rxjava3.internal.operators.single.g gVarG = sVar.o(aVarA).g(new d(p03));
                Intrinsics.checkNotNullExpressionValue(gVarG, "map(...)");
                return gVarG;
            case 5:
                Intrinsics.checkNotNullParameter((Boolean) obj, "<unused var>");
                return (com.quizlet.quizletandroid.data.management.a) obj2;
            case 7:
                return ((B) obj2).get(obj);
            case 11:
                List groups = (List) obj;
                Intrinsics.checkNotNullParameter(groups, "groups");
                if (groups.isEmpty()) {
                    return K.a;
                }
                List<com.quizlet.ui.models.content.carditem.a> listP0 = CollectionsKt.p0(groups, 6);
                ((e) obj2).getClass();
                ArrayList arrayList2 = new ArrayList(C.q(listP0, 10));
                for (com.quizlet.ui.models.content.carditem.a aVar2 : listP0) {
                    arrayList2.add(new C4718n(aVar2, Long.valueOf(aVar2.a), w1.RECENT_FEED));
                }
                return A.b(new z(arrayList2));
            case 12:
                List it3 = (List) obj;
                Intrinsics.checkNotNullParameter(it3, "it");
                ((Y) obj2).getClass();
                return it3.isEmpty() ? new ArrayList() : O.b(CollectionsKt.y0(Y.F(Y.G(it3), P.b, null)));
            case 13:
                Uri it4 = (Uri) obj;
                Intrinsics.checkNotNullParameter(it4, "it");
                String str = CropImageFragment.s;
                CropImageFragment cropImageFragment = (CropImageFragment) obj2;
                try {
                    Bitmap bitmap = MediaStore.Images.Media.getBitmap(cropImageFragment.requireContext().getContentResolver(), it4);
                    com.quizlet.quizletandroid.ui.usersettings.d dVar = cropImageFragment.f;
                    Intrinsics.d(bitmap);
                    return dVar.a(bitmap).m();
                } catch (Exception e) {
                    timber.log.c.a.e(e);
                    return i.k(new NullPointerException("bitmap == null"));
                }
            case 17:
                ApiThreeWrapper apiThreeWrapper = (ApiThreeWrapper) obj;
                Intrinsics.checkNotNullParameter(apiThreeWrapper, "apiThreeWrapper");
                List<RecommendedSetsSchoolCourseBasedResponse> responses = apiThreeWrapper.a;
                if (responses == null) {
                    return K.a;
                }
                com.quizlet.remote.model.set.e eVar = (com.quizlet.remote.model.set.e) ((com.quizlet.remote.model.set.d) obj2).b;
                Intrinsics.checkNotNullParameter(responses, "responses");
                ArrayList arrayList3 = new ArrayList(C.q(responses, 10));
                for (RecommendedSetsSchoolCourseBasedResponse recommendedSetsSchoolCourseBasedResponse : responses) {
                    RecommendedSetsSchoolCourseBasedResponse.RecommendedSetsSchoolCourseBasedModels recommendedSetsSchoolCourseBasedModels = recommendedSetsSchoolCourseBasedResponse.d;
                    List remotes = recommendedSetsSchoolCourseBasedModels.b;
                    com.quizlet.quizletandroid.ui.activitycenter.models.a aVar3 = eVar.a;
                    Intrinsics.checkNotNullParameter(remotes, "remotes");
                    ArrayList arrayListD = eVar.b.d(S.f(aVar3, remotes), recommendedSetsSchoolCourseBasedModels.c);
                    RecommendedSetsSchoolCourseBasedResponse.RecommendedSetsSchoolCourseBasedSource recommendedSetsSchoolCourseBasedSource = recommendedSetsSchoolCourseBasedResponse.e;
                    RemoteSchool remoteSchool = recommendedSetsSchoolCourseBasedSource.a;
                    School schoolA = remoteSchool != null ? com.quizlet.remote.model.school.a.a(remoteSchool) : null;
                    RemoteCourse remoteCourse = recommendedSetsSchoolCourseBasedSource.b;
                    arrayList3.add(new C4162r1(arrayListD, schoolA, remoteCourse != null ? com.quizlet.remote.model.course.c.a(remoteCourse) : null));
                }
                return arrayList3;
            case 18:
                retrofit2.K response = (retrofit2.K) obj;
                Intrinsics.checkNotNullParameter(response, "response");
                r rVar = response.a.f;
                ApiThreeWrapper apiThreeWrapper2 = (ApiThreeWrapper) response.b;
                UserResponse userResponse = apiThreeWrapper2 != null ? (UserResponse) apiThreeWrapper2.a() : null;
                if (userResponse == null || (userModels = userResponse.d) == null || (list = userModels.a) == null) {
                    listF = K.a;
                } else {
                    ArrayList remotes2 = new ArrayList(C.q(list, 10));
                    Iterator it5 = list.iterator();
                    while (it5.hasNext()) {
                        remotes2.add((RemoteUser) it5.next());
                    }
                    Intrinsics.checkNotNullParameter(remotes2, "remotes");
                    listF = S.f((com.quizlet.quizletandroid.ui.activitycenter.models.a) obj2, remotes2);
                }
                if (userResponse != null && (pagingInfo = userResponse.a) != null) {
                    a1I = com.quizlet.quizletandroid.ui.folder.logging.a.i(pagingInfo);
                }
                return new w2(listF, a1I, Q.a(rVar));
        }
    }

    @Override // retrofit2.InterfaceC5181f
    public Type b() {
        return (Type) this.b;
    }

    @Override // dagger.android.b
    public void d(Object obj) {
        ((TextOverlayDialogFragment) obj).q = ((u) this.b).w();
    }

    @Override // com.quizlet.remote.mapper.base.a
    public List e(List list) {
        return T.f(this, list);
    }

    public void f() {
        Socket socket;
        J j = (J) this.b;
        Iterator it2 = ((ConcurrentLinkedQueue) j.e).iterator();
        Intrinsics.checkNotNullExpressionValue(it2, "connections.iterator()");
        while (it2.hasNext()) {
            okhttp3.internal.connection.i connection = (okhttp3.internal.connection.i) it2.next();
            Intrinsics.checkNotNullExpressionValue(connection, "connection");
            synchronized (connection) {
                if (connection.p.isEmpty()) {
                    it2.remove();
                    connection.j = true;
                    socket = connection.d;
                    Intrinsics.d(socket);
                } else {
                    socket = null;
                }
            }
            if (socket != null) {
                okhttp3.internal.b.e(socket);
            }
        }
        if (((ConcurrentLinkedQueue) j.e).isEmpty()) {
            ((okhttp3.internal.concurrent.c) j.c).a();
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object g(java.util.ArrayList r13, assistantMode.refactored.types.AssistantGradingSettings r14, kotlin.coroutines.jvm.internal.c r15) {
        /*
            Method dump skipped, instructions count: 273
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.local.ormlite.models.term.b.g(java.util.ArrayList, assistantMode.refactored.types.AssistantGradingSettings, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    @Override // com.quizlet.remote.mapper.base.a
    /* renamed from: i, reason: merged with bridge method [inline-methods] */
    public ExerciseGroup c(RemoteExerciseGroup remote) {
        Intrinsics.checkNotNullParameter(remote, "remote");
        long j = remote.a;
        List list = remote.e;
        if (list == null) {
            list = K.a;
        }
        return new ExerciseGroup(j, remote.b, remote.c, remote.d, T.f((com.quizlet.quizletandroid.ui.common.images.capture.b) this.b, list));
    }

    @Override // retrofit2.InterfaceC5181f
    public Object j(retrofit2.u uVar) {
        C5183h c5183h = new C5183h(uVar);
        uVar.j(new com.quizlet.quizletandroid.ui.activitycenter.views.i(c5183h, 14));
        return c5183h;
    }

    @Override // com.quizlet.remote.mapper.base.c
    /* renamed from: k, reason: merged with bridge method [inline-methods] */
    public RemoteExerciseGroup h(ExerciseGroup data) {
        Intrinsics.checkNotNullParameter(data, "data");
        long j = data.a;
        ArrayList arrayListG = T.g((com.quizlet.quizletandroid.ui.common.images.capture.b) this.b, data.e);
        return new RemoteExerciseGroup(j, data.c, data.d, data.b, arrayListG);
    }

    public /* synthetic */ b(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    public b(B function) {
        this.a = 7;
        Intrinsics.checkNotNullParameter(function, "function");
        this.b = function;
    }

    public b(EventLogger logger) {
        this.a = 10;
        Intrinsics.checkNotNullParameter(logger, "logger");
        this.b = logger;
    }

    public b(com.quizlet.quizletandroid.ui.common.images.capture.b remoteExerciseMapper) {
        this.a = 15;
        Intrinsics.checkNotNullParameter(remoteExerciseMapper, "remoteExerciseMapper");
        this.b = remoteExerciseMapper;
    }

    public b(com.quizlet.quizletandroid.logging.initializer.a buildLoggingInitializer, com.quizlet.android.logging.a loggingTree) {
        this.a = 6;
        Intrinsics.checkNotNullParameter(buildLoggingInitializer, "buildLoggingInitializer");
        Intrinsics.checkNotNullParameter(loggingTree, "loggingTree");
        this.b = loggingTree;
    }

    public b(com.quizlet.quizletandroid.logging.initializer.a practiceTestsImageDataMapper) {
        this.a = 16;
        Intrinsics.checkNotNullParameter(practiceTestsImageDataMapper, "practiceTestsImageDataMapper");
        this.b = practiceTestsImageDataMapper;
    }

    public b(androidx.work.impl.model.c classContentDataProvider) {
        this.a = 8;
        Intrinsics.checkNotNullParameter(classContentDataProvider, "classContentDataProvider");
        this.b = classContentDataProvider;
    }

    public b(t loginIntentProvider) {
        this.a = 9;
        Intrinsics.checkNotNullParameter(loginIntentProvider, "loginIntentProvider");
        this.b = loginIntentProvider;
    }

    public b(ArrayList graders) {
        this.a = 22;
        Intrinsics.checkNotNullParameter(graders, "graders");
        this.b = graders;
    }

    public b(com.quizlet.infra.legacysyncengine.managers.i saveManager) {
        this.a = 2;
        Intrinsics.checkNotNullParameter(saveManager, "saveManager");
        this.b = saveManager;
    }

    public b() {
        this.a = 20;
        TimeUnit timeUnit = TimeUnit.MINUTES;
        Intrinsics.checkNotNullParameter(timeUnit, "timeUnit");
        J delegate = new J(okhttp3.internal.concurrent.d.h);
        Intrinsics.checkNotNullParameter(delegate, "delegate");
        this.b = delegate;
    }
}
