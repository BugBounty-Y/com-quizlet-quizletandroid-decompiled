package androidx.navigation.compose;

import android.content.ClipData;
import android.content.Intent;
import android.net.Uri;
import androidx.activity.result.ActivityResult;
import androidx.compose.animation.C0292t;
import androidx.navigation.C1291m;
import com.comscore.streaming.EventType;
import com.google.android.gms.internal.mlkit_vision_camera.H1;
import com.google.mlkit.vision.documentscanner.GmsDocumentScanningResult;
import com.quizlet.features.folders.data.C4286i;
import com.quizlet.features.folders.data.C4290k;
import com.quizlet.features.folders.data.C4302q;
import com.quizlet.features.folders.data.C4309u;
import com.quizlet.features.folders.data.K0;
import com.quizlet.features.folders.data.Q;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final /* synthetic */ class B implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Function1 b;

    public /* synthetic */ B(int i, Function1 function1) {
        this.a = i;
        this.b = function1;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        ClipData clipData;
        Uri data;
        List listA;
        Function1 function1 = this.b;
        switch (this.a) {
            case 0:
                C0292t c0292t = (C0292t) obj;
                androidx.navigation.B b = ((C1291m) c0292t.c()).b;
                Intrinsics.e(b, "null cannot be cast to non-null type androidx.navigation.compose.ComposeNavigator.Destination");
                int i = androidx.navigation.B.e;
                for (androidx.navigation.B b2 : H1.b((C1275h) b)) {
                    if (b2 instanceof C1275h) {
                        ((C1275h) b2).getClass();
                    } else if (b2 instanceof C1273f) {
                        ((C1273f) b2).getClass();
                    }
                }
                if (function1 != null) {
                    break;
                }
                break;
            case 1:
                com.quizlet.explanations.databinding.f AndroidViewBinding = (com.quizlet.explanations.databinding.f) obj;
                Intrinsics.checkNotNullParameter(AndroidViewBinding, "$this$AndroidViewBinding");
                function1.invoke(Integer.valueOf(AndroidViewBinding.b.getId()));
                break;
            case 2:
                com.quizlet.explanations.databinding.l AndroidViewBinding2 = (com.quizlet.explanations.databinding.l) obj;
                Intrinsics.checkNotNullParameter(AndroidViewBinding2, "$this$AndroidViewBinding");
                function1.invoke(Integer.valueOf(AndroidViewBinding2.b.getId()));
                break;
            case 3:
                com.quizlet.features.folders.addtofolder.data.f it2 = (com.quizlet.features.folders.addtofolder.data.f) obj;
                Intrinsics.checkNotNullParameter(it2, "it");
                function1.invoke(it2);
                break;
            case 4:
                com.quizlet.features.folders.menu.c it3 = (com.quizlet.features.folders.menu.c) obj;
                Intrinsics.checkNotNullParameter(it3, "it");
                function1.invoke(new C4290k(it3));
                break;
            case 5:
                com.quizlet.features.folders.addtofolder.data.o it4 = (com.quizlet.features.folders.addtofolder.data.o) obj;
                Intrinsics.checkNotNullParameter(it4, "it");
                function1.invoke(new com.quizlet.features.folders.addtofolder.data.a(it4));
                break;
            case 6:
                String it5 = (String) obj;
                Intrinsics.checkNotNullParameter(it5, "it");
                function1.invoke(new com.quizlet.features.folders.addtofolder.data.k(it5));
                break;
            case 7:
                String it6 = (String) obj;
                Intrinsics.checkNotNullParameter(it6, "it");
                function1.invoke(new com.quizlet.features.folders.addtofolder.data.k(it6));
                break;
            case 8:
                com.quizlet.features.infra.folder.menu.data.f it7 = (com.quizlet.features.infra.folder.menu.data.f) obj;
                Intrinsics.checkNotNullParameter(it7, "it");
                function1.invoke(new com.quizlet.features.folders.changetags.data.d(it7));
                break;
            case 9:
                com.quizlet.features.infra.folder.menu.data.f it8 = (com.quizlet.features.infra.folder.menu.data.f) obj;
                Intrinsics.checkNotNullParameter(it8, "it");
                function1.invoke(new com.quizlet.features.folders.changetags.data.d(it8));
                break;
            case 10:
                com.quizlet.features.infra.models.folders.c it9 = (com.quizlet.features.infra.models.folders.c) obj;
                Intrinsics.checkNotNullParameter(it9, "it");
                function1.invoke(new C4286i(it9));
                break;
            case 11:
                function1.invoke(new com.quizlet.features.folders.data.N(((Boolean) obj).booleanValue()));
                break;
            case 12:
                com.quizlet.features.infra.folder.study.data.a studyOption = (com.quizlet.features.infra.folder.study.data.a) obj;
                Intrinsics.checkNotNullParameter(studyOption, "studyOption");
                function1.invoke(new com.quizlet.features.folders.data.K(studyOption));
                break;
            case 13:
                String it10 = (String) obj;
                Intrinsics.checkNotNullParameter(it10, "it");
                function1.invoke(new com.quizlet.features.folders.data.H(it10));
                break;
            case 14:
                String it11 = (String) obj;
                Intrinsics.checkNotNullParameter(it11, "it");
                function1.invoke(new com.quizlet.features.folders.data.H(it11));
                break;
            case 15:
                com.quizlet.data.interactor.folderstudymaterial.g action = (com.quizlet.data.interactor.folderstudymaterial.g) obj;
                Intrinsics.checkNotNullParameter(action, "action");
                function1.invoke(new Q(action));
                break;
            case 16:
                com.quizlet.features.folders.menu.i it12 = (com.quizlet.features.folders.menu.i) obj;
                Intrinsics.checkNotNullParameter(it12, "it");
                function1.invoke(new C4309u(it12));
                break;
            case 17:
                com.quizlet.features.folders.menu.q it13 = (com.quizlet.features.folders.menu.q) obj;
                Intrinsics.checkNotNullParameter(it13, "it");
                function1.invoke(new C4302q(it13));
                break;
            case 18:
                K0 newSortType = (K0) obj;
                Intrinsics.checkNotNullParameter(newSortType, "newSortType");
                function1.invoke(new com.quizlet.features.folders.data.I(newSortType));
                break;
            case 19:
                com.quizlet.ui.models.content.listitem.o it14 = (com.quizlet.ui.models.content.listitem.o) obj;
                Intrinsics.checkNotNullParameter(it14, "it");
                function1.invoke(new com.quizlet.features.home.data.d(it14));
                break;
            case 20:
                String it15 = (String) obj;
                Intrinsics.checkNotNullParameter(it15, "it");
                function1.invoke(new com.quizlet.features.home.data.b(it15));
                break;
            case 21:
                ActivityResult result = (ActivityResult) obj;
                Intrinsics.checkNotNullParameter(result, "result");
                if (result.a == -1) {
                    Intent intent = result.b;
                    if (intent != null && (data = intent.getData()) != null) {
                        function1.invoke(kotlin.collections.A.b(data));
                    }
                    if (intent != null && (clipData = intent.getClipData()) != null) {
                        ArrayList arrayList = new ArrayList();
                        int itemCount = clipData.getItemCount() > 1 ? 1 : clipData.getItemCount();
                        for (int i2 = 0; i2 < itemCount; i2++) {
                            Uri uri = clipData.getItemAt(i2).getUri();
                            Intrinsics.checkNotNullExpressionValue(uri, "getUri(...)");
                            arrayList.add(uri);
                        }
                        function1.invoke(arrayList);
                    }
                }
                break;
            case EventType.WINDOW_STATE /* 22 */:
                ActivityResult it16 = (ActivityResult) obj;
                Intrinsics.checkNotNullParameter(it16, "it");
                if (it16.a == -1) {
                    Intent intent2 = it16.b;
                    GmsDocumentScanningResult gmsDocumentScanningResult = intent2 != null ? (GmsDocumentScanningResult) intent2.getParcelableExtra("extra_scanning_result") : null;
                    if (gmsDocumentScanningResult != null && (listA = gmsDocumentScanningResult.a()) != null) {
                        ArrayList arrayList2 = new ArrayList(kotlin.collections.C.q(listA, 10));
                        Iterator it17 = listA.iterator();
                        while (it17.hasNext()) {
                            Uri uriA = ((GmsDocumentScanningResult.Page) it17.next()).a();
                            Intrinsics.checkNotNullExpressionValue(uriA, "getImageUri(...)");
                            arrayList2.add(uriA);
                        }
                        function1.invoke(arrayList2);
                    }
                }
                break;
            case EventType.AUDIO /* 23 */:
                Boolean bool = (Boolean) obj;
                bool.booleanValue();
                function1.invoke(bool);
                break;
            case EventType.VIDEO /* 24 */:
                function1.invoke(new com.quizlet.features.infra.folder.create.coursefolder.data.d(((Boolean) obj).booleanValue()));
                break;
            case EventType.SUBS /* 25 */:
                function1.invoke(new com.quizlet.features.infra.folder.create.coursefolder.data.d(((Boolean) obj).booleanValue()));
                break;
            case EventType.CDN /* 26 */:
                com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.viewmodel.c schoolSelectedData = (com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.viewmodel.c) obj;
                Intrinsics.checkNotNullParameter(schoolSelectedData, "schoolSelectedData");
                function1.invoke(new com.quizlet.features.infra.folder.create.coursefolder.data.i(schoolSelectedData));
                break;
            case 27:
                com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.viewmodel.a courseSelectedData = (com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.viewmodel.a) obj;
                Intrinsics.checkNotNullParameter(courseSelectedData, "courseSelectedData");
                function1.invoke(new com.quizlet.features.infra.folder.create.coursefolder.data.e(courseSelectedData));
                break;
            case 28:
                String it18 = (String) obj;
                Intrinsics.checkNotNullParameter(it18, "it");
                function1.invoke(new com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.l(it18));
                break;
            default:
                com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.f it19 = (com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.f) obj;
                Intrinsics.checkNotNullParameter(it19, "it");
                function1.invoke(new com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data.k(it19, 0L));
                break;
        }
        return Unit.a;
    }
}
