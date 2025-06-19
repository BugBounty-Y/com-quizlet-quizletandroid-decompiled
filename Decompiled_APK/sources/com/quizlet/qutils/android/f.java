package com.quizlet.qutils.android;

import android.content.Context;
import androidx.compose.ui.graphics.S;
import androidx.compose.ui.semantics.t;
import androidx.compose.ui.semantics.v;
import androidx.compose.ui.text.H;
import com.comscore.streaming.EventType;
import com.quizlet.data.model.C4122e;
import com.quizlet.data.model.C4134i;
import com.quizlet.data.model.C4146m;
import com.quizlet.data.model.C4158q;
import com.quizlet.data.model.Y;
import com.quizlet.data.model.f2;
import com.quizlet.remote.model.folder.RemoteFolder;
import com.quizlet.remote.model.folderstudymaterial.FolderStudyMaterialResponse;
import com.quizlet.uicommon.ui.common.widgets.QSegmentedControl;
import com.sdk.growthbook.features.FeaturesDataSource;
import com.sdk.growthbook.sandbox.CachingAndroid;
import com.sdk.growthbook.utils.CryptoKt;
import com.skydoves.balloon.Balloon;
import java.io.File;
import java.util.List;
import kotlin.Unit;
import kotlin.collections.K;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.json.g;

/* loaded from: classes3.dex */
public final /* synthetic */ class f implements Function1 {
    public final /* synthetic */ int a;

    public /* synthetic */ f(int i) {
        this.a = i;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        List list;
        List list2;
        switch (this.a) {
            case 0:
                File it2 = (File) obj;
                Intrinsics.checkNotNullParameter(it2, "it");
                return Boolean.valueOf(it2.isFile() && it2.exists());
            case 1:
                String it3 = (String) obj;
                Intrinsics.checkNotNullParameter(it3, "it");
                return it3;
            case 2:
                Exception it4 = (Exception) obj;
                Intrinsics.checkNotNullParameter(it4, "it");
                return new C4146m(it4);
            case 3:
                Exception it5 = (Exception) obj;
                Intrinsics.checkNotNullParameter(it5, "it");
                return new C4134i(it5);
            case 4:
                Exception it6 = (Exception) obj;
                Intrinsics.checkNotNullParameter(it6, "it");
                return new C4122e(it6);
            case 5:
                Exception it7 = (Exception) obj;
                Intrinsics.checkNotNullParameter(it7, "it");
                return new C4158q(it7);
            case 6:
                Exception it8 = (Exception) obj;
                Intrinsics.checkNotNullParameter(it8, "it");
                return new f2(it8);
            case 7:
                Y it9 = (Y) obj;
                Intrinsics.checkNotNullParameter(it9, "it");
                return it9.b();
            case 8:
                RemoteFolder it10 = (RemoteFolder) obj;
                Intrinsics.checkNotNullParameter(it10, "it");
                return it10.a;
            case 9:
                FolderStudyMaterialResponse it11 = (FolderStudyMaterialResponse) obj;
                Intrinsics.checkNotNullParameter(it11, "it");
                FolderStudyMaterialResponse.Models models = it11.d;
                return (models == null || (list = models.a) == null) ? K.a : list;
            case 10:
                FolderStudyMaterialResponse it12 = (FolderStudyMaterialResponse) obj;
                Intrinsics.checkNotNullParameter(it12, "it");
                FolderStudyMaterialResponse.Models models2 = it12.d;
                return (models2 == null || (list2 = models2.a) == null) ? K.a : list2;
            case 11:
                Intrinsics.checkNotNullParameter((H) obj, "it");
                return Unit.a;
            case 12:
                Intrinsics.checkNotNullParameter((H) obj, "it");
                return Unit.a;
            case 13:
                Intrinsics.checkNotNullParameter((String) obj, "it");
                return Unit.a;
            case 14:
                Intrinsics.checkNotNullParameter((String) obj, "it");
                return Unit.a;
            case 15:
                com.quizlet.ui.models.search.a it13 = (com.quizlet.ui.models.search.a) obj;
                Intrinsics.checkNotNullParameter(it13, "it");
                return it13.getKey();
            case 16:
                com.quizlet.ui.models.search.a it14 = (com.quizlet.ui.models.search.a) obj;
                Intrinsics.checkNotNullParameter(it14, "it");
                return it14.getKey();
            case 17:
                com.quizlet.ui.models.search.a it15 = (com.quizlet.ui.models.search.a) obj;
                Intrinsics.checkNotNullParameter(it15, "it");
                return it15.getKey();
            case 18:
                com.quizlet.ui.models.search.a it16 = (com.quizlet.ui.models.search.a) obj;
                Intrinsics.checkNotNullParameter(it16, "it");
                return it16.getKey();
            case 19:
                com.quizlet.ui.models.search.a it17 = (com.quizlet.ui.models.search.a) obj;
                Intrinsics.checkNotNullParameter(it17, "it");
                return it17.getKey();
            case 20:
                Intrinsics.checkNotNullParameter((v) obj, "$this$semantics");
                return Unit.a;
            case 21:
                ((Integer) obj).intValue();
                return Unit.a;
            case EventType.WINDOW_STATE /* 22 */:
                v semantics = (v) obj;
                Intrinsics.checkNotNullParameter(semantics, "$this$semantics");
                t.h(semantics, 1);
                return Unit.a;
            case EventType.AUDIO /* 23 */:
                v semantics2 = (v) obj;
                Intrinsics.checkNotNullParameter(semantics2, "$this$semantics");
                t.h(semantics2, 0);
                return Unit.a;
            case EventType.VIDEO /* 24 */:
                S graphicsLayer = (S) obj;
                Intrinsics.checkNotNullParameter(graphicsLayer, "$this$graphicsLayer");
                if (graphicsLayer.q != 1) {
                    graphicsLayer.a |= 32768;
                    graphicsLayer.q = 1;
                }
                return Unit.a;
            case EventType.SUBS /* 25 */:
                Context it18 = (Context) obj;
                Intrinsics.checkNotNullParameter(it18, "it");
                return new QSegmentedControl(it18, null, 6);
            case EventType.CDN /* 26 */:
                Intrinsics.checkNotNullParameter((Balloon.Builder) obj, "<this>");
                return Unit.a;
            case 27:
                return FeaturesDataSource._get_jsonParser_$lambda$0((g) obj);
            case 28:
                return CachingAndroid.json$lambda$0((g) obj);
            default:
                return CryptoKt.encryptToFeaturesDataModel$lambda$0((g) obj);
        }
    }
}
