package com.quizlet.quizletandroid.ui.diagramming;

import android.content.res.Resources;
import android.graphics.drawable.Drawable;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import androidx.activity.v;
import androidx.constraintlayout.widget.Guideline;
import androidx.coordinatorlayout.widget.CoordinatorLayout;
import androidx.core.widget.NestedScrollView;
import androidx.fragment.app.AbstractC1136h0;
import androidx.fragment.app.C1121a;
import com.bumptech.glide.Glide;
import com.bumptech.glide.m;
import com.google.android.gms.internal.mlkit_vision_barcode.A7;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3188k6;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.google.android.gms.measurement.internal.Z;
import com.google.android.material.bottomsheet.BottomSheetBehavior;
import com.quizlet.db.data.caches.UserInfoCache;
import com.quizlet.db.data.models.base.SortOption;
import com.quizlet.db.data.models.persisted.DBSelectedTerm;
import com.quizlet.db.data.models.persisted.DBTerm;
import com.quizlet.db.data.models.persisted.base.Models;
import com.quizlet.db.data.models.persisted.fields.DBStudySetFields;
import com.quizlet.generated.enums.O1;
import com.quizlet.infra.legacysyncengine.datasources.w;
import com.quizlet.partskit.widgets.QTextView;
import com.quizlet.partskit.widgets.icon.QStarIconView;
import com.quizlet.partskit.widgets.icon.StatefulIconFontTextView;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.databinding.C4613q;
import com.quizlet.studiablemodels.diagrams.DiagramData;
import io.reactivex.rxjava3.core.o;
import io.reactivex.rxjava3.core.p;
import io.reactivex.rxjava3.internal.operators.observable.J;
import io.reactivex.rxjava3.internal.operators.observable.W;
import io.reactivex.rxjava3.subjects.r;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import kotlin.Metadata;
import kotlin.Pair;
import kotlin.collections.C;
import kotlin.collections.V;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.l;
import kotlin.text.StringsKt;
import kotlin.u;

@Metadata
/* loaded from: classes3.dex */
public final class DiagramOverviewActivity extends com.quizlet.ads.ui.activity.d implements com.quizlet.infra.legacysyncengine.datasources.b, h, com.quizlet.quizletandroid.ui.common.adapter.e {
    public static final /* synthetic */ int o1 = 0;
    public final u A;
    public com.quizlet.features.infra.legacyadapter.databinding.f B;
    public final u C;
    public final u D;
    public final u E;
    public UserInfoCache F;
    public com.quizlet.quizletandroid.managers.audio.h G;
    public com.quizlet.infra.legacysyncengine.net.f H;
    public com.quizlet.infra.legacysyncengine.net.c I;
    public com.quizlet.infra.legacysyncengine.managers.d J;
    public o K;
    public com.quizlet.qutils.image.loading.a L;
    public io.ktor.client.plugins.api.d M;
    public final r V;
    public final r W;
    public final r X;
    public final io.reactivex.rxjava3.subjects.d Y;
    public com.quizlet.data.repository.login.a Z;
    public final u c1;
    public final u d1;
    public final u e1;
    public final u f1;
    public long g1;
    public Object h1;
    public final io.reactivex.rxjava3.disposables.a i1;
    public final b j1;
    public final b k1;
    public final b l1;
    public final com.quizlet.infra.legacysyncengine.models.serializers.a m1;
    public final com.google.android.material.bottomsheet.f n1;
    public final u q;
    public final u r;
    public final u s;
    public final u t;
    public final u u;
    public final u v;
    public final u w;
    public final u x;
    public final u y;
    public final u z;

    /* JADX WARN: Type inference failed for: r0v40, types: [com.quizlet.quizletandroid.ui.diagramming.b] */
    /* JADX WARN: Type inference failed for: r0v41, types: [com.quizlet.quizletandroid.ui.diagramming.b] */
    /* JADX WARN: Type inference failed for: r0v42, types: [com.quizlet.quizletandroid.ui.diagramming.b] */
    public DiagramOverviewActivity() {
        super(3);
        final int i = 13;
        this.q = l.b(new Function0(this) { // from class: com.quizlet.quizletandroid.ui.diagramming.a
            public final /* synthetic */ DiagramOverviewActivity b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                DiagramOverviewActivity diagramOverviewActivity = this.b;
                switch (i) {
                    case 0:
                        int i2 = DiagramOverviewActivity.o1;
                        com.quizlet.infra.legacysyncengine.net.c cVar = diagramOverviewActivity.I;
                        if (cVar == null) {
                            Intrinsics.m("loader");
                            throw null;
                        }
                        long jLongValue = ((Number) diagramOverviewActivity.d1.getValue()).longValue();
                        UserInfoCache userInfoCache = diagramOverviewActivity.F;
                        if (userInfoCache != null) {
                            return new w(cVar, jLongValue, userInfoCache.getPersonId(), false, SortOption.ORIGINAL);
                        }
                        Intrinsics.m("userInfoCache");
                        throw null;
                    case 1:
                        int i3 = DiagramOverviewActivity.o1;
                        return Long.valueOf(diagramOverviewActivity.getIntent().getLongExtra("setId", 0L));
                    case 2:
                        return BottomSheetBehavior.C((NestedScrollView) diagramOverviewActivity.r.getValue());
                    case 3:
                        DiagramOverviewActivity diagramOverviewActivity2 = this.b;
                        com.quizlet.infra.legacysyncengine.managers.d dVar = diagramOverviewActivity2.J;
                        if (dVar == null) {
                            Intrinsics.m("loggedInUserManager");
                            throw null;
                        }
                        com.quizlet.infra.legacysyncengine.net.f fVar = diagramOverviewActivity2.H;
                        if (fVar == null) {
                            Intrinsics.m("syncDispatcher");
                            throw null;
                        }
                        com.quizlet.quizletandroid.managers.audio.h hVar = diagramOverviewActivity2.G;
                        if (hVar == null) {
                            Intrinsics.m("audioManager");
                            throw null;
                        }
                        io.ktor.client.plugins.api.d dVar2 = diagramOverviewActivity2.M;
                        if (dVar2 != null) {
                            return new com.quizlet.quizletandroid.ui.common.adapter.presenter.e(dVar, fVar, hVar, diagramOverviewActivity2, dVar2);
                        }
                        Intrinsics.m("audioPlayFailureManager");
                        throw null;
                    case 4:
                        int i4 = DiagramOverviewActivity.o1;
                        NestedScrollView setpageDiagramBottomSheet = ((C4613q) diagramOverviewActivity.K()).c;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramBottomSheet, "setpageDiagramBottomSheet");
                        return setpageDiagramBottomSheet;
                    case 5:
                        int i5 = DiagramOverviewActivity.o1;
                        StatefulIconFontTextView setpageDiagramDetailsAudio = ((C4613q) diagramOverviewActivity.K()).d;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsAudio, "setpageDiagramDetailsAudio");
                        return setpageDiagramDetailsAudio;
                    case 6:
                        int i6 = DiagramOverviewActivity.o1;
                        ImageView setpageDiagramDetailsClose = ((C4613q) diagramOverviewActivity.K()).e;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsClose, "setpageDiagramDetailsClose");
                        return setpageDiagramDetailsClose;
                    case 7:
                        int i7 = DiagramOverviewActivity.o1;
                        DiagramView setpageDiagramDetailsDiagramView = ((C4613q) diagramOverviewActivity.K()).f;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsDiagramView, "setpageDiagramDetailsDiagramView");
                        return setpageDiagramDetailsDiagramView;
                    case 8:
                        int i8 = DiagramOverviewActivity.o1;
                        QStarIconView setpageDiagramDetailsStar = ((C4613q) diagramOverviewActivity.K()).g;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsStar, "setpageDiagramDetailsStar");
                        return setpageDiagramDetailsStar;
                    case 9:
                        int i9 = DiagramOverviewActivity.o1;
                        QTextView setpageDiagramDetailsTermDefinition = ((C4613q) diagramOverviewActivity.K()).h;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsTermDefinition, "setpageDiagramDetailsTermDefinition");
                        return setpageDiagramDetailsTermDefinition;
                    case 10:
                        int i10 = DiagramOverviewActivity.o1;
                        QTextView setpageDiagramDetailsTermDefinitionLabel = ((C4613q) diagramOverviewActivity.K()).i;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsTermDefinitionLabel, "setpageDiagramDetailsTermDefinitionLabel");
                        return setpageDiagramDetailsTermDefinitionLabel;
                    case 11:
                        int i11 = DiagramOverviewActivity.o1;
                        QTextView setpageDiagramDetailsTermDiagramLabel = ((C4613q) diagramOverviewActivity.K()).j;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsTermDiagramLabel, "setpageDiagramDetailsTermDiagramLabel");
                        return setpageDiagramDetailsTermDiagramLabel;
                    case 12:
                        int i12 = DiagramOverviewActivity.o1;
                        ImageView setpageDiagramDetailsTermImage = ((C4613q) diagramOverviewActivity.K()).k;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsTermImage, "setpageDiagramDetailsTermImage");
                        return setpageDiagramDetailsTermImage;
                    case 13:
                        int i13 = DiagramOverviewActivity.o1;
                        View contentOverlay = ((C4613q) diagramOverviewActivity.K()).b;
                        Intrinsics.checkNotNullExpressionValue(contentOverlay, "contentOverlay");
                        return contentOverlay;
                    case 14:
                        int i14 = DiagramOverviewActivity.o1;
                        QTextView setpageDiagramDetailsTermWord = ((C4613q) diagramOverviewActivity.K()).l;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsTermWord, "setpageDiagramDetailsTermWord");
                        return setpageDiagramDetailsTermWord;
                    case 15:
                        com.quizlet.features.infra.legacyadapter.databinding.f fVar2 = diagramOverviewActivity.B;
                        if (fVar2 == null) {
                            Intrinsics.m("studyModeSettingsToolbarBinding");
                            throw null;
                        }
                        QTextView studyModeSettingsToolbarTitle = (QTextView) fVar2.d;
                        Intrinsics.checkNotNullExpressionValue(studyModeSettingsToolbarTitle, "studyModeSettingsToolbarTitle");
                        return studyModeSettingsToolbarTitle;
                    case 16:
                        com.quizlet.features.infra.legacyadapter.databinding.f fVar3 = diagramOverviewActivity.B;
                        if (fVar3 == null) {
                            Intrinsics.m("studyModeSettingsToolbarBinding");
                            throw null;
                        }
                        FrameLayout studyModeSettingsToolbarUpButton = (FrameLayout) fVar3.c;
                        Intrinsics.checkNotNullExpressionValue(studyModeSettingsToolbarUpButton, "studyModeSettingsToolbarUpButton");
                        return studyModeSettingsToolbarUpButton;
                    default:
                        com.quizlet.features.infra.legacyadapter.databinding.f fVar4 = diagramOverviewActivity.B;
                        if (fVar4 == null) {
                            Intrinsics.m("studyModeSettingsToolbarBinding");
                            throw null;
                        }
                        ImageView studyModeSettingsToolbarUpIcon = (ImageView) fVar4.e;
                        Intrinsics.checkNotNullExpressionValue(studyModeSettingsToolbarUpIcon, "studyModeSettingsToolbarUpIcon");
                        return studyModeSettingsToolbarUpIcon;
                }
            }
        });
        final int i2 = 4;
        this.r = l.b(new Function0(this) { // from class: com.quizlet.quizletandroid.ui.diagramming.a
            public final /* synthetic */ DiagramOverviewActivity b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                DiagramOverviewActivity diagramOverviewActivity = this.b;
                switch (i2) {
                    case 0:
                        int i22 = DiagramOverviewActivity.o1;
                        com.quizlet.infra.legacysyncengine.net.c cVar = diagramOverviewActivity.I;
                        if (cVar == null) {
                            Intrinsics.m("loader");
                            throw null;
                        }
                        long jLongValue = ((Number) diagramOverviewActivity.d1.getValue()).longValue();
                        UserInfoCache userInfoCache = diagramOverviewActivity.F;
                        if (userInfoCache != null) {
                            return new w(cVar, jLongValue, userInfoCache.getPersonId(), false, SortOption.ORIGINAL);
                        }
                        Intrinsics.m("userInfoCache");
                        throw null;
                    case 1:
                        int i3 = DiagramOverviewActivity.o1;
                        return Long.valueOf(diagramOverviewActivity.getIntent().getLongExtra("setId", 0L));
                    case 2:
                        return BottomSheetBehavior.C((NestedScrollView) diagramOverviewActivity.r.getValue());
                    case 3:
                        DiagramOverviewActivity diagramOverviewActivity2 = this.b;
                        com.quizlet.infra.legacysyncengine.managers.d dVar = diagramOverviewActivity2.J;
                        if (dVar == null) {
                            Intrinsics.m("loggedInUserManager");
                            throw null;
                        }
                        com.quizlet.infra.legacysyncengine.net.f fVar = diagramOverviewActivity2.H;
                        if (fVar == null) {
                            Intrinsics.m("syncDispatcher");
                            throw null;
                        }
                        com.quizlet.quizletandroid.managers.audio.h hVar = diagramOverviewActivity2.G;
                        if (hVar == null) {
                            Intrinsics.m("audioManager");
                            throw null;
                        }
                        io.ktor.client.plugins.api.d dVar2 = diagramOverviewActivity2.M;
                        if (dVar2 != null) {
                            return new com.quizlet.quizletandroid.ui.common.adapter.presenter.e(dVar, fVar, hVar, diagramOverviewActivity2, dVar2);
                        }
                        Intrinsics.m("audioPlayFailureManager");
                        throw null;
                    case 4:
                        int i4 = DiagramOverviewActivity.o1;
                        NestedScrollView setpageDiagramBottomSheet = ((C4613q) diagramOverviewActivity.K()).c;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramBottomSheet, "setpageDiagramBottomSheet");
                        return setpageDiagramBottomSheet;
                    case 5:
                        int i5 = DiagramOverviewActivity.o1;
                        StatefulIconFontTextView setpageDiagramDetailsAudio = ((C4613q) diagramOverviewActivity.K()).d;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsAudio, "setpageDiagramDetailsAudio");
                        return setpageDiagramDetailsAudio;
                    case 6:
                        int i6 = DiagramOverviewActivity.o1;
                        ImageView setpageDiagramDetailsClose = ((C4613q) diagramOverviewActivity.K()).e;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsClose, "setpageDiagramDetailsClose");
                        return setpageDiagramDetailsClose;
                    case 7:
                        int i7 = DiagramOverviewActivity.o1;
                        DiagramView setpageDiagramDetailsDiagramView = ((C4613q) diagramOverviewActivity.K()).f;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsDiagramView, "setpageDiagramDetailsDiagramView");
                        return setpageDiagramDetailsDiagramView;
                    case 8:
                        int i8 = DiagramOverviewActivity.o1;
                        QStarIconView setpageDiagramDetailsStar = ((C4613q) diagramOverviewActivity.K()).g;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsStar, "setpageDiagramDetailsStar");
                        return setpageDiagramDetailsStar;
                    case 9:
                        int i9 = DiagramOverviewActivity.o1;
                        QTextView setpageDiagramDetailsTermDefinition = ((C4613q) diagramOverviewActivity.K()).h;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsTermDefinition, "setpageDiagramDetailsTermDefinition");
                        return setpageDiagramDetailsTermDefinition;
                    case 10:
                        int i10 = DiagramOverviewActivity.o1;
                        QTextView setpageDiagramDetailsTermDefinitionLabel = ((C4613q) diagramOverviewActivity.K()).i;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsTermDefinitionLabel, "setpageDiagramDetailsTermDefinitionLabel");
                        return setpageDiagramDetailsTermDefinitionLabel;
                    case 11:
                        int i11 = DiagramOverviewActivity.o1;
                        QTextView setpageDiagramDetailsTermDiagramLabel = ((C4613q) diagramOverviewActivity.K()).j;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsTermDiagramLabel, "setpageDiagramDetailsTermDiagramLabel");
                        return setpageDiagramDetailsTermDiagramLabel;
                    case 12:
                        int i12 = DiagramOverviewActivity.o1;
                        ImageView setpageDiagramDetailsTermImage = ((C4613q) diagramOverviewActivity.K()).k;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsTermImage, "setpageDiagramDetailsTermImage");
                        return setpageDiagramDetailsTermImage;
                    case 13:
                        int i13 = DiagramOverviewActivity.o1;
                        View contentOverlay = ((C4613q) diagramOverviewActivity.K()).b;
                        Intrinsics.checkNotNullExpressionValue(contentOverlay, "contentOverlay");
                        return contentOverlay;
                    case 14:
                        int i14 = DiagramOverviewActivity.o1;
                        QTextView setpageDiagramDetailsTermWord = ((C4613q) diagramOverviewActivity.K()).l;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsTermWord, "setpageDiagramDetailsTermWord");
                        return setpageDiagramDetailsTermWord;
                    case 15:
                        com.quizlet.features.infra.legacyadapter.databinding.f fVar2 = diagramOverviewActivity.B;
                        if (fVar2 == null) {
                            Intrinsics.m("studyModeSettingsToolbarBinding");
                            throw null;
                        }
                        QTextView studyModeSettingsToolbarTitle = (QTextView) fVar2.d;
                        Intrinsics.checkNotNullExpressionValue(studyModeSettingsToolbarTitle, "studyModeSettingsToolbarTitle");
                        return studyModeSettingsToolbarTitle;
                    case 16:
                        com.quizlet.features.infra.legacyadapter.databinding.f fVar3 = diagramOverviewActivity.B;
                        if (fVar3 == null) {
                            Intrinsics.m("studyModeSettingsToolbarBinding");
                            throw null;
                        }
                        FrameLayout studyModeSettingsToolbarUpButton = (FrameLayout) fVar3.c;
                        Intrinsics.checkNotNullExpressionValue(studyModeSettingsToolbarUpButton, "studyModeSettingsToolbarUpButton");
                        return studyModeSettingsToolbarUpButton;
                    default:
                        com.quizlet.features.infra.legacyadapter.databinding.f fVar4 = diagramOverviewActivity.B;
                        if (fVar4 == null) {
                            Intrinsics.m("studyModeSettingsToolbarBinding");
                            throw null;
                        }
                        ImageView studyModeSettingsToolbarUpIcon = (ImageView) fVar4.e;
                        Intrinsics.checkNotNullExpressionValue(studyModeSettingsToolbarUpIcon, "studyModeSettingsToolbarUpIcon");
                        return studyModeSettingsToolbarUpIcon;
                }
            }
        });
        final int i3 = 5;
        this.s = l.b(new Function0(this) { // from class: com.quizlet.quizletandroid.ui.diagramming.a
            public final /* synthetic */ DiagramOverviewActivity b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                DiagramOverviewActivity diagramOverviewActivity = this.b;
                switch (i3) {
                    case 0:
                        int i22 = DiagramOverviewActivity.o1;
                        com.quizlet.infra.legacysyncengine.net.c cVar = diagramOverviewActivity.I;
                        if (cVar == null) {
                            Intrinsics.m("loader");
                            throw null;
                        }
                        long jLongValue = ((Number) diagramOverviewActivity.d1.getValue()).longValue();
                        UserInfoCache userInfoCache = diagramOverviewActivity.F;
                        if (userInfoCache != null) {
                            return new w(cVar, jLongValue, userInfoCache.getPersonId(), false, SortOption.ORIGINAL);
                        }
                        Intrinsics.m("userInfoCache");
                        throw null;
                    case 1:
                        int i32 = DiagramOverviewActivity.o1;
                        return Long.valueOf(diagramOverviewActivity.getIntent().getLongExtra("setId", 0L));
                    case 2:
                        return BottomSheetBehavior.C((NestedScrollView) diagramOverviewActivity.r.getValue());
                    case 3:
                        DiagramOverviewActivity diagramOverviewActivity2 = this.b;
                        com.quizlet.infra.legacysyncengine.managers.d dVar = diagramOverviewActivity2.J;
                        if (dVar == null) {
                            Intrinsics.m("loggedInUserManager");
                            throw null;
                        }
                        com.quizlet.infra.legacysyncengine.net.f fVar = diagramOverviewActivity2.H;
                        if (fVar == null) {
                            Intrinsics.m("syncDispatcher");
                            throw null;
                        }
                        com.quizlet.quizletandroid.managers.audio.h hVar = diagramOverviewActivity2.G;
                        if (hVar == null) {
                            Intrinsics.m("audioManager");
                            throw null;
                        }
                        io.ktor.client.plugins.api.d dVar2 = diagramOverviewActivity2.M;
                        if (dVar2 != null) {
                            return new com.quizlet.quizletandroid.ui.common.adapter.presenter.e(dVar, fVar, hVar, diagramOverviewActivity2, dVar2);
                        }
                        Intrinsics.m("audioPlayFailureManager");
                        throw null;
                    case 4:
                        int i4 = DiagramOverviewActivity.o1;
                        NestedScrollView setpageDiagramBottomSheet = ((C4613q) diagramOverviewActivity.K()).c;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramBottomSheet, "setpageDiagramBottomSheet");
                        return setpageDiagramBottomSheet;
                    case 5:
                        int i5 = DiagramOverviewActivity.o1;
                        StatefulIconFontTextView setpageDiagramDetailsAudio = ((C4613q) diagramOverviewActivity.K()).d;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsAudio, "setpageDiagramDetailsAudio");
                        return setpageDiagramDetailsAudio;
                    case 6:
                        int i6 = DiagramOverviewActivity.o1;
                        ImageView setpageDiagramDetailsClose = ((C4613q) diagramOverviewActivity.K()).e;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsClose, "setpageDiagramDetailsClose");
                        return setpageDiagramDetailsClose;
                    case 7:
                        int i7 = DiagramOverviewActivity.o1;
                        DiagramView setpageDiagramDetailsDiagramView = ((C4613q) diagramOverviewActivity.K()).f;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsDiagramView, "setpageDiagramDetailsDiagramView");
                        return setpageDiagramDetailsDiagramView;
                    case 8:
                        int i8 = DiagramOverviewActivity.o1;
                        QStarIconView setpageDiagramDetailsStar = ((C4613q) diagramOverviewActivity.K()).g;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsStar, "setpageDiagramDetailsStar");
                        return setpageDiagramDetailsStar;
                    case 9:
                        int i9 = DiagramOverviewActivity.o1;
                        QTextView setpageDiagramDetailsTermDefinition = ((C4613q) diagramOverviewActivity.K()).h;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsTermDefinition, "setpageDiagramDetailsTermDefinition");
                        return setpageDiagramDetailsTermDefinition;
                    case 10:
                        int i10 = DiagramOverviewActivity.o1;
                        QTextView setpageDiagramDetailsTermDefinitionLabel = ((C4613q) diagramOverviewActivity.K()).i;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsTermDefinitionLabel, "setpageDiagramDetailsTermDefinitionLabel");
                        return setpageDiagramDetailsTermDefinitionLabel;
                    case 11:
                        int i11 = DiagramOverviewActivity.o1;
                        QTextView setpageDiagramDetailsTermDiagramLabel = ((C4613q) diagramOverviewActivity.K()).j;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsTermDiagramLabel, "setpageDiagramDetailsTermDiagramLabel");
                        return setpageDiagramDetailsTermDiagramLabel;
                    case 12:
                        int i12 = DiagramOverviewActivity.o1;
                        ImageView setpageDiagramDetailsTermImage = ((C4613q) diagramOverviewActivity.K()).k;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsTermImage, "setpageDiagramDetailsTermImage");
                        return setpageDiagramDetailsTermImage;
                    case 13:
                        int i13 = DiagramOverviewActivity.o1;
                        View contentOverlay = ((C4613q) diagramOverviewActivity.K()).b;
                        Intrinsics.checkNotNullExpressionValue(contentOverlay, "contentOverlay");
                        return contentOverlay;
                    case 14:
                        int i14 = DiagramOverviewActivity.o1;
                        QTextView setpageDiagramDetailsTermWord = ((C4613q) diagramOverviewActivity.K()).l;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsTermWord, "setpageDiagramDetailsTermWord");
                        return setpageDiagramDetailsTermWord;
                    case 15:
                        com.quizlet.features.infra.legacyadapter.databinding.f fVar2 = diagramOverviewActivity.B;
                        if (fVar2 == null) {
                            Intrinsics.m("studyModeSettingsToolbarBinding");
                            throw null;
                        }
                        QTextView studyModeSettingsToolbarTitle = (QTextView) fVar2.d;
                        Intrinsics.checkNotNullExpressionValue(studyModeSettingsToolbarTitle, "studyModeSettingsToolbarTitle");
                        return studyModeSettingsToolbarTitle;
                    case 16:
                        com.quizlet.features.infra.legacyadapter.databinding.f fVar3 = diagramOverviewActivity.B;
                        if (fVar3 == null) {
                            Intrinsics.m("studyModeSettingsToolbarBinding");
                            throw null;
                        }
                        FrameLayout studyModeSettingsToolbarUpButton = (FrameLayout) fVar3.c;
                        Intrinsics.checkNotNullExpressionValue(studyModeSettingsToolbarUpButton, "studyModeSettingsToolbarUpButton");
                        return studyModeSettingsToolbarUpButton;
                    default:
                        com.quizlet.features.infra.legacyadapter.databinding.f fVar4 = diagramOverviewActivity.B;
                        if (fVar4 == null) {
                            Intrinsics.m("studyModeSettingsToolbarBinding");
                            throw null;
                        }
                        ImageView studyModeSettingsToolbarUpIcon = (ImageView) fVar4.e;
                        Intrinsics.checkNotNullExpressionValue(studyModeSettingsToolbarUpIcon, "studyModeSettingsToolbarUpIcon");
                        return studyModeSettingsToolbarUpIcon;
                }
            }
        });
        final int i4 = 6;
        this.t = l.b(new Function0(this) { // from class: com.quizlet.quizletandroid.ui.diagramming.a
            public final /* synthetic */ DiagramOverviewActivity b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                DiagramOverviewActivity diagramOverviewActivity = this.b;
                switch (i4) {
                    case 0:
                        int i22 = DiagramOverviewActivity.o1;
                        com.quizlet.infra.legacysyncengine.net.c cVar = diagramOverviewActivity.I;
                        if (cVar == null) {
                            Intrinsics.m("loader");
                            throw null;
                        }
                        long jLongValue = ((Number) diagramOverviewActivity.d1.getValue()).longValue();
                        UserInfoCache userInfoCache = diagramOverviewActivity.F;
                        if (userInfoCache != null) {
                            return new w(cVar, jLongValue, userInfoCache.getPersonId(), false, SortOption.ORIGINAL);
                        }
                        Intrinsics.m("userInfoCache");
                        throw null;
                    case 1:
                        int i32 = DiagramOverviewActivity.o1;
                        return Long.valueOf(diagramOverviewActivity.getIntent().getLongExtra("setId", 0L));
                    case 2:
                        return BottomSheetBehavior.C((NestedScrollView) diagramOverviewActivity.r.getValue());
                    case 3:
                        DiagramOverviewActivity diagramOverviewActivity2 = this.b;
                        com.quizlet.infra.legacysyncengine.managers.d dVar = diagramOverviewActivity2.J;
                        if (dVar == null) {
                            Intrinsics.m("loggedInUserManager");
                            throw null;
                        }
                        com.quizlet.infra.legacysyncengine.net.f fVar = diagramOverviewActivity2.H;
                        if (fVar == null) {
                            Intrinsics.m("syncDispatcher");
                            throw null;
                        }
                        com.quizlet.quizletandroid.managers.audio.h hVar = diagramOverviewActivity2.G;
                        if (hVar == null) {
                            Intrinsics.m("audioManager");
                            throw null;
                        }
                        io.ktor.client.plugins.api.d dVar2 = diagramOverviewActivity2.M;
                        if (dVar2 != null) {
                            return new com.quizlet.quizletandroid.ui.common.adapter.presenter.e(dVar, fVar, hVar, diagramOverviewActivity2, dVar2);
                        }
                        Intrinsics.m("audioPlayFailureManager");
                        throw null;
                    case 4:
                        int i42 = DiagramOverviewActivity.o1;
                        NestedScrollView setpageDiagramBottomSheet = ((C4613q) diagramOverviewActivity.K()).c;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramBottomSheet, "setpageDiagramBottomSheet");
                        return setpageDiagramBottomSheet;
                    case 5:
                        int i5 = DiagramOverviewActivity.o1;
                        StatefulIconFontTextView setpageDiagramDetailsAudio = ((C4613q) diagramOverviewActivity.K()).d;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsAudio, "setpageDiagramDetailsAudio");
                        return setpageDiagramDetailsAudio;
                    case 6:
                        int i6 = DiagramOverviewActivity.o1;
                        ImageView setpageDiagramDetailsClose = ((C4613q) diagramOverviewActivity.K()).e;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsClose, "setpageDiagramDetailsClose");
                        return setpageDiagramDetailsClose;
                    case 7:
                        int i7 = DiagramOverviewActivity.o1;
                        DiagramView setpageDiagramDetailsDiagramView = ((C4613q) diagramOverviewActivity.K()).f;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsDiagramView, "setpageDiagramDetailsDiagramView");
                        return setpageDiagramDetailsDiagramView;
                    case 8:
                        int i8 = DiagramOverviewActivity.o1;
                        QStarIconView setpageDiagramDetailsStar = ((C4613q) diagramOverviewActivity.K()).g;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsStar, "setpageDiagramDetailsStar");
                        return setpageDiagramDetailsStar;
                    case 9:
                        int i9 = DiagramOverviewActivity.o1;
                        QTextView setpageDiagramDetailsTermDefinition = ((C4613q) diagramOverviewActivity.K()).h;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsTermDefinition, "setpageDiagramDetailsTermDefinition");
                        return setpageDiagramDetailsTermDefinition;
                    case 10:
                        int i10 = DiagramOverviewActivity.o1;
                        QTextView setpageDiagramDetailsTermDefinitionLabel = ((C4613q) diagramOverviewActivity.K()).i;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsTermDefinitionLabel, "setpageDiagramDetailsTermDefinitionLabel");
                        return setpageDiagramDetailsTermDefinitionLabel;
                    case 11:
                        int i11 = DiagramOverviewActivity.o1;
                        QTextView setpageDiagramDetailsTermDiagramLabel = ((C4613q) diagramOverviewActivity.K()).j;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsTermDiagramLabel, "setpageDiagramDetailsTermDiagramLabel");
                        return setpageDiagramDetailsTermDiagramLabel;
                    case 12:
                        int i12 = DiagramOverviewActivity.o1;
                        ImageView setpageDiagramDetailsTermImage = ((C4613q) diagramOverviewActivity.K()).k;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsTermImage, "setpageDiagramDetailsTermImage");
                        return setpageDiagramDetailsTermImage;
                    case 13:
                        int i13 = DiagramOverviewActivity.o1;
                        View contentOverlay = ((C4613q) diagramOverviewActivity.K()).b;
                        Intrinsics.checkNotNullExpressionValue(contentOverlay, "contentOverlay");
                        return contentOverlay;
                    case 14:
                        int i14 = DiagramOverviewActivity.o1;
                        QTextView setpageDiagramDetailsTermWord = ((C4613q) diagramOverviewActivity.K()).l;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsTermWord, "setpageDiagramDetailsTermWord");
                        return setpageDiagramDetailsTermWord;
                    case 15:
                        com.quizlet.features.infra.legacyadapter.databinding.f fVar2 = diagramOverviewActivity.B;
                        if (fVar2 == null) {
                            Intrinsics.m("studyModeSettingsToolbarBinding");
                            throw null;
                        }
                        QTextView studyModeSettingsToolbarTitle = (QTextView) fVar2.d;
                        Intrinsics.checkNotNullExpressionValue(studyModeSettingsToolbarTitle, "studyModeSettingsToolbarTitle");
                        return studyModeSettingsToolbarTitle;
                    case 16:
                        com.quizlet.features.infra.legacyadapter.databinding.f fVar3 = diagramOverviewActivity.B;
                        if (fVar3 == null) {
                            Intrinsics.m("studyModeSettingsToolbarBinding");
                            throw null;
                        }
                        FrameLayout studyModeSettingsToolbarUpButton = (FrameLayout) fVar3.c;
                        Intrinsics.checkNotNullExpressionValue(studyModeSettingsToolbarUpButton, "studyModeSettingsToolbarUpButton");
                        return studyModeSettingsToolbarUpButton;
                    default:
                        com.quizlet.features.infra.legacyadapter.databinding.f fVar4 = diagramOverviewActivity.B;
                        if (fVar4 == null) {
                            Intrinsics.m("studyModeSettingsToolbarBinding");
                            throw null;
                        }
                        ImageView studyModeSettingsToolbarUpIcon = (ImageView) fVar4.e;
                        Intrinsics.checkNotNullExpressionValue(studyModeSettingsToolbarUpIcon, "studyModeSettingsToolbarUpIcon");
                        return studyModeSettingsToolbarUpIcon;
                }
            }
        });
        final int i5 = 7;
        this.u = l.b(new Function0(this) { // from class: com.quizlet.quizletandroid.ui.diagramming.a
            public final /* synthetic */ DiagramOverviewActivity b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                DiagramOverviewActivity diagramOverviewActivity = this.b;
                switch (i5) {
                    case 0:
                        int i22 = DiagramOverviewActivity.o1;
                        com.quizlet.infra.legacysyncengine.net.c cVar = diagramOverviewActivity.I;
                        if (cVar == null) {
                            Intrinsics.m("loader");
                            throw null;
                        }
                        long jLongValue = ((Number) diagramOverviewActivity.d1.getValue()).longValue();
                        UserInfoCache userInfoCache = diagramOverviewActivity.F;
                        if (userInfoCache != null) {
                            return new w(cVar, jLongValue, userInfoCache.getPersonId(), false, SortOption.ORIGINAL);
                        }
                        Intrinsics.m("userInfoCache");
                        throw null;
                    case 1:
                        int i32 = DiagramOverviewActivity.o1;
                        return Long.valueOf(diagramOverviewActivity.getIntent().getLongExtra("setId", 0L));
                    case 2:
                        return BottomSheetBehavior.C((NestedScrollView) diagramOverviewActivity.r.getValue());
                    case 3:
                        DiagramOverviewActivity diagramOverviewActivity2 = this.b;
                        com.quizlet.infra.legacysyncengine.managers.d dVar = diagramOverviewActivity2.J;
                        if (dVar == null) {
                            Intrinsics.m("loggedInUserManager");
                            throw null;
                        }
                        com.quizlet.infra.legacysyncengine.net.f fVar = diagramOverviewActivity2.H;
                        if (fVar == null) {
                            Intrinsics.m("syncDispatcher");
                            throw null;
                        }
                        com.quizlet.quizletandroid.managers.audio.h hVar = diagramOverviewActivity2.G;
                        if (hVar == null) {
                            Intrinsics.m("audioManager");
                            throw null;
                        }
                        io.ktor.client.plugins.api.d dVar2 = diagramOverviewActivity2.M;
                        if (dVar2 != null) {
                            return new com.quizlet.quizletandroid.ui.common.adapter.presenter.e(dVar, fVar, hVar, diagramOverviewActivity2, dVar2);
                        }
                        Intrinsics.m("audioPlayFailureManager");
                        throw null;
                    case 4:
                        int i42 = DiagramOverviewActivity.o1;
                        NestedScrollView setpageDiagramBottomSheet = ((C4613q) diagramOverviewActivity.K()).c;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramBottomSheet, "setpageDiagramBottomSheet");
                        return setpageDiagramBottomSheet;
                    case 5:
                        int i52 = DiagramOverviewActivity.o1;
                        StatefulIconFontTextView setpageDiagramDetailsAudio = ((C4613q) diagramOverviewActivity.K()).d;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsAudio, "setpageDiagramDetailsAudio");
                        return setpageDiagramDetailsAudio;
                    case 6:
                        int i6 = DiagramOverviewActivity.o1;
                        ImageView setpageDiagramDetailsClose = ((C4613q) diagramOverviewActivity.K()).e;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsClose, "setpageDiagramDetailsClose");
                        return setpageDiagramDetailsClose;
                    case 7:
                        int i7 = DiagramOverviewActivity.o1;
                        DiagramView setpageDiagramDetailsDiagramView = ((C4613q) diagramOverviewActivity.K()).f;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsDiagramView, "setpageDiagramDetailsDiagramView");
                        return setpageDiagramDetailsDiagramView;
                    case 8:
                        int i8 = DiagramOverviewActivity.o1;
                        QStarIconView setpageDiagramDetailsStar = ((C4613q) diagramOverviewActivity.K()).g;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsStar, "setpageDiagramDetailsStar");
                        return setpageDiagramDetailsStar;
                    case 9:
                        int i9 = DiagramOverviewActivity.o1;
                        QTextView setpageDiagramDetailsTermDefinition = ((C4613q) diagramOverviewActivity.K()).h;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsTermDefinition, "setpageDiagramDetailsTermDefinition");
                        return setpageDiagramDetailsTermDefinition;
                    case 10:
                        int i10 = DiagramOverviewActivity.o1;
                        QTextView setpageDiagramDetailsTermDefinitionLabel = ((C4613q) diagramOverviewActivity.K()).i;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsTermDefinitionLabel, "setpageDiagramDetailsTermDefinitionLabel");
                        return setpageDiagramDetailsTermDefinitionLabel;
                    case 11:
                        int i11 = DiagramOverviewActivity.o1;
                        QTextView setpageDiagramDetailsTermDiagramLabel = ((C4613q) diagramOverviewActivity.K()).j;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsTermDiagramLabel, "setpageDiagramDetailsTermDiagramLabel");
                        return setpageDiagramDetailsTermDiagramLabel;
                    case 12:
                        int i12 = DiagramOverviewActivity.o1;
                        ImageView setpageDiagramDetailsTermImage = ((C4613q) diagramOverviewActivity.K()).k;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsTermImage, "setpageDiagramDetailsTermImage");
                        return setpageDiagramDetailsTermImage;
                    case 13:
                        int i13 = DiagramOverviewActivity.o1;
                        View contentOverlay = ((C4613q) diagramOverviewActivity.K()).b;
                        Intrinsics.checkNotNullExpressionValue(contentOverlay, "contentOverlay");
                        return contentOverlay;
                    case 14:
                        int i14 = DiagramOverviewActivity.o1;
                        QTextView setpageDiagramDetailsTermWord = ((C4613q) diagramOverviewActivity.K()).l;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsTermWord, "setpageDiagramDetailsTermWord");
                        return setpageDiagramDetailsTermWord;
                    case 15:
                        com.quizlet.features.infra.legacyadapter.databinding.f fVar2 = diagramOverviewActivity.B;
                        if (fVar2 == null) {
                            Intrinsics.m("studyModeSettingsToolbarBinding");
                            throw null;
                        }
                        QTextView studyModeSettingsToolbarTitle = (QTextView) fVar2.d;
                        Intrinsics.checkNotNullExpressionValue(studyModeSettingsToolbarTitle, "studyModeSettingsToolbarTitle");
                        return studyModeSettingsToolbarTitle;
                    case 16:
                        com.quizlet.features.infra.legacyadapter.databinding.f fVar3 = diagramOverviewActivity.B;
                        if (fVar3 == null) {
                            Intrinsics.m("studyModeSettingsToolbarBinding");
                            throw null;
                        }
                        FrameLayout studyModeSettingsToolbarUpButton = (FrameLayout) fVar3.c;
                        Intrinsics.checkNotNullExpressionValue(studyModeSettingsToolbarUpButton, "studyModeSettingsToolbarUpButton");
                        return studyModeSettingsToolbarUpButton;
                    default:
                        com.quizlet.features.infra.legacyadapter.databinding.f fVar4 = diagramOverviewActivity.B;
                        if (fVar4 == null) {
                            Intrinsics.m("studyModeSettingsToolbarBinding");
                            throw null;
                        }
                        ImageView studyModeSettingsToolbarUpIcon = (ImageView) fVar4.e;
                        Intrinsics.checkNotNullExpressionValue(studyModeSettingsToolbarUpIcon, "studyModeSettingsToolbarUpIcon");
                        return studyModeSettingsToolbarUpIcon;
                }
            }
        });
        final int i6 = 8;
        this.v = l.b(new Function0(this) { // from class: com.quizlet.quizletandroid.ui.diagramming.a
            public final /* synthetic */ DiagramOverviewActivity b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                DiagramOverviewActivity diagramOverviewActivity = this.b;
                switch (i6) {
                    case 0:
                        int i22 = DiagramOverviewActivity.o1;
                        com.quizlet.infra.legacysyncengine.net.c cVar = diagramOverviewActivity.I;
                        if (cVar == null) {
                            Intrinsics.m("loader");
                            throw null;
                        }
                        long jLongValue = ((Number) diagramOverviewActivity.d1.getValue()).longValue();
                        UserInfoCache userInfoCache = diagramOverviewActivity.F;
                        if (userInfoCache != null) {
                            return new w(cVar, jLongValue, userInfoCache.getPersonId(), false, SortOption.ORIGINAL);
                        }
                        Intrinsics.m("userInfoCache");
                        throw null;
                    case 1:
                        int i32 = DiagramOverviewActivity.o1;
                        return Long.valueOf(diagramOverviewActivity.getIntent().getLongExtra("setId", 0L));
                    case 2:
                        return BottomSheetBehavior.C((NestedScrollView) diagramOverviewActivity.r.getValue());
                    case 3:
                        DiagramOverviewActivity diagramOverviewActivity2 = this.b;
                        com.quizlet.infra.legacysyncengine.managers.d dVar = diagramOverviewActivity2.J;
                        if (dVar == null) {
                            Intrinsics.m("loggedInUserManager");
                            throw null;
                        }
                        com.quizlet.infra.legacysyncengine.net.f fVar = diagramOverviewActivity2.H;
                        if (fVar == null) {
                            Intrinsics.m("syncDispatcher");
                            throw null;
                        }
                        com.quizlet.quizletandroid.managers.audio.h hVar = diagramOverviewActivity2.G;
                        if (hVar == null) {
                            Intrinsics.m("audioManager");
                            throw null;
                        }
                        io.ktor.client.plugins.api.d dVar2 = diagramOverviewActivity2.M;
                        if (dVar2 != null) {
                            return new com.quizlet.quizletandroid.ui.common.adapter.presenter.e(dVar, fVar, hVar, diagramOverviewActivity2, dVar2);
                        }
                        Intrinsics.m("audioPlayFailureManager");
                        throw null;
                    case 4:
                        int i42 = DiagramOverviewActivity.o1;
                        NestedScrollView setpageDiagramBottomSheet = ((C4613q) diagramOverviewActivity.K()).c;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramBottomSheet, "setpageDiagramBottomSheet");
                        return setpageDiagramBottomSheet;
                    case 5:
                        int i52 = DiagramOverviewActivity.o1;
                        StatefulIconFontTextView setpageDiagramDetailsAudio = ((C4613q) diagramOverviewActivity.K()).d;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsAudio, "setpageDiagramDetailsAudio");
                        return setpageDiagramDetailsAudio;
                    case 6:
                        int i62 = DiagramOverviewActivity.o1;
                        ImageView setpageDiagramDetailsClose = ((C4613q) diagramOverviewActivity.K()).e;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsClose, "setpageDiagramDetailsClose");
                        return setpageDiagramDetailsClose;
                    case 7:
                        int i7 = DiagramOverviewActivity.o1;
                        DiagramView setpageDiagramDetailsDiagramView = ((C4613q) diagramOverviewActivity.K()).f;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsDiagramView, "setpageDiagramDetailsDiagramView");
                        return setpageDiagramDetailsDiagramView;
                    case 8:
                        int i8 = DiagramOverviewActivity.o1;
                        QStarIconView setpageDiagramDetailsStar = ((C4613q) diagramOverviewActivity.K()).g;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsStar, "setpageDiagramDetailsStar");
                        return setpageDiagramDetailsStar;
                    case 9:
                        int i9 = DiagramOverviewActivity.o1;
                        QTextView setpageDiagramDetailsTermDefinition = ((C4613q) diagramOverviewActivity.K()).h;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsTermDefinition, "setpageDiagramDetailsTermDefinition");
                        return setpageDiagramDetailsTermDefinition;
                    case 10:
                        int i10 = DiagramOverviewActivity.o1;
                        QTextView setpageDiagramDetailsTermDefinitionLabel = ((C4613q) diagramOverviewActivity.K()).i;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsTermDefinitionLabel, "setpageDiagramDetailsTermDefinitionLabel");
                        return setpageDiagramDetailsTermDefinitionLabel;
                    case 11:
                        int i11 = DiagramOverviewActivity.o1;
                        QTextView setpageDiagramDetailsTermDiagramLabel = ((C4613q) diagramOverviewActivity.K()).j;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsTermDiagramLabel, "setpageDiagramDetailsTermDiagramLabel");
                        return setpageDiagramDetailsTermDiagramLabel;
                    case 12:
                        int i12 = DiagramOverviewActivity.o1;
                        ImageView setpageDiagramDetailsTermImage = ((C4613q) diagramOverviewActivity.K()).k;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsTermImage, "setpageDiagramDetailsTermImage");
                        return setpageDiagramDetailsTermImage;
                    case 13:
                        int i13 = DiagramOverviewActivity.o1;
                        View contentOverlay = ((C4613q) diagramOverviewActivity.K()).b;
                        Intrinsics.checkNotNullExpressionValue(contentOverlay, "contentOverlay");
                        return contentOverlay;
                    case 14:
                        int i14 = DiagramOverviewActivity.o1;
                        QTextView setpageDiagramDetailsTermWord = ((C4613q) diagramOverviewActivity.K()).l;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsTermWord, "setpageDiagramDetailsTermWord");
                        return setpageDiagramDetailsTermWord;
                    case 15:
                        com.quizlet.features.infra.legacyadapter.databinding.f fVar2 = diagramOverviewActivity.B;
                        if (fVar2 == null) {
                            Intrinsics.m("studyModeSettingsToolbarBinding");
                            throw null;
                        }
                        QTextView studyModeSettingsToolbarTitle = (QTextView) fVar2.d;
                        Intrinsics.checkNotNullExpressionValue(studyModeSettingsToolbarTitle, "studyModeSettingsToolbarTitle");
                        return studyModeSettingsToolbarTitle;
                    case 16:
                        com.quizlet.features.infra.legacyadapter.databinding.f fVar3 = diagramOverviewActivity.B;
                        if (fVar3 == null) {
                            Intrinsics.m("studyModeSettingsToolbarBinding");
                            throw null;
                        }
                        FrameLayout studyModeSettingsToolbarUpButton = (FrameLayout) fVar3.c;
                        Intrinsics.checkNotNullExpressionValue(studyModeSettingsToolbarUpButton, "studyModeSettingsToolbarUpButton");
                        return studyModeSettingsToolbarUpButton;
                    default:
                        com.quizlet.features.infra.legacyadapter.databinding.f fVar4 = diagramOverviewActivity.B;
                        if (fVar4 == null) {
                            Intrinsics.m("studyModeSettingsToolbarBinding");
                            throw null;
                        }
                        ImageView studyModeSettingsToolbarUpIcon = (ImageView) fVar4.e;
                        Intrinsics.checkNotNullExpressionValue(studyModeSettingsToolbarUpIcon, "studyModeSettingsToolbarUpIcon");
                        return studyModeSettingsToolbarUpIcon;
                }
            }
        });
        final int i7 = 9;
        this.w = l.b(new Function0(this) { // from class: com.quizlet.quizletandroid.ui.diagramming.a
            public final /* synthetic */ DiagramOverviewActivity b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                DiagramOverviewActivity diagramOverviewActivity = this.b;
                switch (i7) {
                    case 0:
                        int i22 = DiagramOverviewActivity.o1;
                        com.quizlet.infra.legacysyncengine.net.c cVar = diagramOverviewActivity.I;
                        if (cVar == null) {
                            Intrinsics.m("loader");
                            throw null;
                        }
                        long jLongValue = ((Number) diagramOverviewActivity.d1.getValue()).longValue();
                        UserInfoCache userInfoCache = diagramOverviewActivity.F;
                        if (userInfoCache != null) {
                            return new w(cVar, jLongValue, userInfoCache.getPersonId(), false, SortOption.ORIGINAL);
                        }
                        Intrinsics.m("userInfoCache");
                        throw null;
                    case 1:
                        int i32 = DiagramOverviewActivity.o1;
                        return Long.valueOf(diagramOverviewActivity.getIntent().getLongExtra("setId", 0L));
                    case 2:
                        return BottomSheetBehavior.C((NestedScrollView) diagramOverviewActivity.r.getValue());
                    case 3:
                        DiagramOverviewActivity diagramOverviewActivity2 = this.b;
                        com.quizlet.infra.legacysyncengine.managers.d dVar = diagramOverviewActivity2.J;
                        if (dVar == null) {
                            Intrinsics.m("loggedInUserManager");
                            throw null;
                        }
                        com.quizlet.infra.legacysyncengine.net.f fVar = diagramOverviewActivity2.H;
                        if (fVar == null) {
                            Intrinsics.m("syncDispatcher");
                            throw null;
                        }
                        com.quizlet.quizletandroid.managers.audio.h hVar = diagramOverviewActivity2.G;
                        if (hVar == null) {
                            Intrinsics.m("audioManager");
                            throw null;
                        }
                        io.ktor.client.plugins.api.d dVar2 = diagramOverviewActivity2.M;
                        if (dVar2 != null) {
                            return new com.quizlet.quizletandroid.ui.common.adapter.presenter.e(dVar, fVar, hVar, diagramOverviewActivity2, dVar2);
                        }
                        Intrinsics.m("audioPlayFailureManager");
                        throw null;
                    case 4:
                        int i42 = DiagramOverviewActivity.o1;
                        NestedScrollView setpageDiagramBottomSheet = ((C4613q) diagramOverviewActivity.K()).c;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramBottomSheet, "setpageDiagramBottomSheet");
                        return setpageDiagramBottomSheet;
                    case 5:
                        int i52 = DiagramOverviewActivity.o1;
                        StatefulIconFontTextView setpageDiagramDetailsAudio = ((C4613q) diagramOverviewActivity.K()).d;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsAudio, "setpageDiagramDetailsAudio");
                        return setpageDiagramDetailsAudio;
                    case 6:
                        int i62 = DiagramOverviewActivity.o1;
                        ImageView setpageDiagramDetailsClose = ((C4613q) diagramOverviewActivity.K()).e;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsClose, "setpageDiagramDetailsClose");
                        return setpageDiagramDetailsClose;
                    case 7:
                        int i72 = DiagramOverviewActivity.o1;
                        DiagramView setpageDiagramDetailsDiagramView = ((C4613q) diagramOverviewActivity.K()).f;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsDiagramView, "setpageDiagramDetailsDiagramView");
                        return setpageDiagramDetailsDiagramView;
                    case 8:
                        int i8 = DiagramOverviewActivity.o1;
                        QStarIconView setpageDiagramDetailsStar = ((C4613q) diagramOverviewActivity.K()).g;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsStar, "setpageDiagramDetailsStar");
                        return setpageDiagramDetailsStar;
                    case 9:
                        int i9 = DiagramOverviewActivity.o1;
                        QTextView setpageDiagramDetailsTermDefinition = ((C4613q) diagramOverviewActivity.K()).h;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsTermDefinition, "setpageDiagramDetailsTermDefinition");
                        return setpageDiagramDetailsTermDefinition;
                    case 10:
                        int i10 = DiagramOverviewActivity.o1;
                        QTextView setpageDiagramDetailsTermDefinitionLabel = ((C4613q) diagramOverviewActivity.K()).i;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsTermDefinitionLabel, "setpageDiagramDetailsTermDefinitionLabel");
                        return setpageDiagramDetailsTermDefinitionLabel;
                    case 11:
                        int i11 = DiagramOverviewActivity.o1;
                        QTextView setpageDiagramDetailsTermDiagramLabel = ((C4613q) diagramOverviewActivity.K()).j;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsTermDiagramLabel, "setpageDiagramDetailsTermDiagramLabel");
                        return setpageDiagramDetailsTermDiagramLabel;
                    case 12:
                        int i12 = DiagramOverviewActivity.o1;
                        ImageView setpageDiagramDetailsTermImage = ((C4613q) diagramOverviewActivity.K()).k;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsTermImage, "setpageDiagramDetailsTermImage");
                        return setpageDiagramDetailsTermImage;
                    case 13:
                        int i13 = DiagramOverviewActivity.o1;
                        View contentOverlay = ((C4613q) diagramOverviewActivity.K()).b;
                        Intrinsics.checkNotNullExpressionValue(contentOverlay, "contentOverlay");
                        return contentOverlay;
                    case 14:
                        int i14 = DiagramOverviewActivity.o1;
                        QTextView setpageDiagramDetailsTermWord = ((C4613q) diagramOverviewActivity.K()).l;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsTermWord, "setpageDiagramDetailsTermWord");
                        return setpageDiagramDetailsTermWord;
                    case 15:
                        com.quizlet.features.infra.legacyadapter.databinding.f fVar2 = diagramOverviewActivity.B;
                        if (fVar2 == null) {
                            Intrinsics.m("studyModeSettingsToolbarBinding");
                            throw null;
                        }
                        QTextView studyModeSettingsToolbarTitle = (QTextView) fVar2.d;
                        Intrinsics.checkNotNullExpressionValue(studyModeSettingsToolbarTitle, "studyModeSettingsToolbarTitle");
                        return studyModeSettingsToolbarTitle;
                    case 16:
                        com.quizlet.features.infra.legacyadapter.databinding.f fVar3 = diagramOverviewActivity.B;
                        if (fVar3 == null) {
                            Intrinsics.m("studyModeSettingsToolbarBinding");
                            throw null;
                        }
                        FrameLayout studyModeSettingsToolbarUpButton = (FrameLayout) fVar3.c;
                        Intrinsics.checkNotNullExpressionValue(studyModeSettingsToolbarUpButton, "studyModeSettingsToolbarUpButton");
                        return studyModeSettingsToolbarUpButton;
                    default:
                        com.quizlet.features.infra.legacyadapter.databinding.f fVar4 = diagramOverviewActivity.B;
                        if (fVar4 == null) {
                            Intrinsics.m("studyModeSettingsToolbarBinding");
                            throw null;
                        }
                        ImageView studyModeSettingsToolbarUpIcon = (ImageView) fVar4.e;
                        Intrinsics.checkNotNullExpressionValue(studyModeSettingsToolbarUpIcon, "studyModeSettingsToolbarUpIcon");
                        return studyModeSettingsToolbarUpIcon;
                }
            }
        });
        final int i8 = 10;
        this.x = l.b(new Function0(this) { // from class: com.quizlet.quizletandroid.ui.diagramming.a
            public final /* synthetic */ DiagramOverviewActivity b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                DiagramOverviewActivity diagramOverviewActivity = this.b;
                switch (i8) {
                    case 0:
                        int i22 = DiagramOverviewActivity.o1;
                        com.quizlet.infra.legacysyncengine.net.c cVar = diagramOverviewActivity.I;
                        if (cVar == null) {
                            Intrinsics.m("loader");
                            throw null;
                        }
                        long jLongValue = ((Number) diagramOverviewActivity.d1.getValue()).longValue();
                        UserInfoCache userInfoCache = diagramOverviewActivity.F;
                        if (userInfoCache != null) {
                            return new w(cVar, jLongValue, userInfoCache.getPersonId(), false, SortOption.ORIGINAL);
                        }
                        Intrinsics.m("userInfoCache");
                        throw null;
                    case 1:
                        int i32 = DiagramOverviewActivity.o1;
                        return Long.valueOf(diagramOverviewActivity.getIntent().getLongExtra("setId", 0L));
                    case 2:
                        return BottomSheetBehavior.C((NestedScrollView) diagramOverviewActivity.r.getValue());
                    case 3:
                        DiagramOverviewActivity diagramOverviewActivity2 = this.b;
                        com.quizlet.infra.legacysyncengine.managers.d dVar = diagramOverviewActivity2.J;
                        if (dVar == null) {
                            Intrinsics.m("loggedInUserManager");
                            throw null;
                        }
                        com.quizlet.infra.legacysyncengine.net.f fVar = diagramOverviewActivity2.H;
                        if (fVar == null) {
                            Intrinsics.m("syncDispatcher");
                            throw null;
                        }
                        com.quizlet.quizletandroid.managers.audio.h hVar = diagramOverviewActivity2.G;
                        if (hVar == null) {
                            Intrinsics.m("audioManager");
                            throw null;
                        }
                        io.ktor.client.plugins.api.d dVar2 = diagramOverviewActivity2.M;
                        if (dVar2 != null) {
                            return new com.quizlet.quizletandroid.ui.common.adapter.presenter.e(dVar, fVar, hVar, diagramOverviewActivity2, dVar2);
                        }
                        Intrinsics.m("audioPlayFailureManager");
                        throw null;
                    case 4:
                        int i42 = DiagramOverviewActivity.o1;
                        NestedScrollView setpageDiagramBottomSheet = ((C4613q) diagramOverviewActivity.K()).c;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramBottomSheet, "setpageDiagramBottomSheet");
                        return setpageDiagramBottomSheet;
                    case 5:
                        int i52 = DiagramOverviewActivity.o1;
                        StatefulIconFontTextView setpageDiagramDetailsAudio = ((C4613q) diagramOverviewActivity.K()).d;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsAudio, "setpageDiagramDetailsAudio");
                        return setpageDiagramDetailsAudio;
                    case 6:
                        int i62 = DiagramOverviewActivity.o1;
                        ImageView setpageDiagramDetailsClose = ((C4613q) diagramOverviewActivity.K()).e;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsClose, "setpageDiagramDetailsClose");
                        return setpageDiagramDetailsClose;
                    case 7:
                        int i72 = DiagramOverviewActivity.o1;
                        DiagramView setpageDiagramDetailsDiagramView = ((C4613q) diagramOverviewActivity.K()).f;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsDiagramView, "setpageDiagramDetailsDiagramView");
                        return setpageDiagramDetailsDiagramView;
                    case 8:
                        int i82 = DiagramOverviewActivity.o1;
                        QStarIconView setpageDiagramDetailsStar = ((C4613q) diagramOverviewActivity.K()).g;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsStar, "setpageDiagramDetailsStar");
                        return setpageDiagramDetailsStar;
                    case 9:
                        int i9 = DiagramOverviewActivity.o1;
                        QTextView setpageDiagramDetailsTermDefinition = ((C4613q) diagramOverviewActivity.K()).h;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsTermDefinition, "setpageDiagramDetailsTermDefinition");
                        return setpageDiagramDetailsTermDefinition;
                    case 10:
                        int i10 = DiagramOverviewActivity.o1;
                        QTextView setpageDiagramDetailsTermDefinitionLabel = ((C4613q) diagramOverviewActivity.K()).i;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsTermDefinitionLabel, "setpageDiagramDetailsTermDefinitionLabel");
                        return setpageDiagramDetailsTermDefinitionLabel;
                    case 11:
                        int i11 = DiagramOverviewActivity.o1;
                        QTextView setpageDiagramDetailsTermDiagramLabel = ((C4613q) diagramOverviewActivity.K()).j;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsTermDiagramLabel, "setpageDiagramDetailsTermDiagramLabel");
                        return setpageDiagramDetailsTermDiagramLabel;
                    case 12:
                        int i12 = DiagramOverviewActivity.o1;
                        ImageView setpageDiagramDetailsTermImage = ((C4613q) diagramOverviewActivity.K()).k;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsTermImage, "setpageDiagramDetailsTermImage");
                        return setpageDiagramDetailsTermImage;
                    case 13:
                        int i13 = DiagramOverviewActivity.o1;
                        View contentOverlay = ((C4613q) diagramOverviewActivity.K()).b;
                        Intrinsics.checkNotNullExpressionValue(contentOverlay, "contentOverlay");
                        return contentOverlay;
                    case 14:
                        int i14 = DiagramOverviewActivity.o1;
                        QTextView setpageDiagramDetailsTermWord = ((C4613q) diagramOverviewActivity.K()).l;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsTermWord, "setpageDiagramDetailsTermWord");
                        return setpageDiagramDetailsTermWord;
                    case 15:
                        com.quizlet.features.infra.legacyadapter.databinding.f fVar2 = diagramOverviewActivity.B;
                        if (fVar2 == null) {
                            Intrinsics.m("studyModeSettingsToolbarBinding");
                            throw null;
                        }
                        QTextView studyModeSettingsToolbarTitle = (QTextView) fVar2.d;
                        Intrinsics.checkNotNullExpressionValue(studyModeSettingsToolbarTitle, "studyModeSettingsToolbarTitle");
                        return studyModeSettingsToolbarTitle;
                    case 16:
                        com.quizlet.features.infra.legacyadapter.databinding.f fVar3 = diagramOverviewActivity.B;
                        if (fVar3 == null) {
                            Intrinsics.m("studyModeSettingsToolbarBinding");
                            throw null;
                        }
                        FrameLayout studyModeSettingsToolbarUpButton = (FrameLayout) fVar3.c;
                        Intrinsics.checkNotNullExpressionValue(studyModeSettingsToolbarUpButton, "studyModeSettingsToolbarUpButton");
                        return studyModeSettingsToolbarUpButton;
                    default:
                        com.quizlet.features.infra.legacyadapter.databinding.f fVar4 = diagramOverviewActivity.B;
                        if (fVar4 == null) {
                            Intrinsics.m("studyModeSettingsToolbarBinding");
                            throw null;
                        }
                        ImageView studyModeSettingsToolbarUpIcon = (ImageView) fVar4.e;
                        Intrinsics.checkNotNullExpressionValue(studyModeSettingsToolbarUpIcon, "studyModeSettingsToolbarUpIcon");
                        return studyModeSettingsToolbarUpIcon;
                }
            }
        });
        final int i9 = 11;
        this.y = l.b(new Function0(this) { // from class: com.quizlet.quizletandroid.ui.diagramming.a
            public final /* synthetic */ DiagramOverviewActivity b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                DiagramOverviewActivity diagramOverviewActivity = this.b;
                switch (i9) {
                    case 0:
                        int i22 = DiagramOverviewActivity.o1;
                        com.quizlet.infra.legacysyncengine.net.c cVar = diagramOverviewActivity.I;
                        if (cVar == null) {
                            Intrinsics.m("loader");
                            throw null;
                        }
                        long jLongValue = ((Number) diagramOverviewActivity.d1.getValue()).longValue();
                        UserInfoCache userInfoCache = diagramOverviewActivity.F;
                        if (userInfoCache != null) {
                            return new w(cVar, jLongValue, userInfoCache.getPersonId(), false, SortOption.ORIGINAL);
                        }
                        Intrinsics.m("userInfoCache");
                        throw null;
                    case 1:
                        int i32 = DiagramOverviewActivity.o1;
                        return Long.valueOf(diagramOverviewActivity.getIntent().getLongExtra("setId", 0L));
                    case 2:
                        return BottomSheetBehavior.C((NestedScrollView) diagramOverviewActivity.r.getValue());
                    case 3:
                        DiagramOverviewActivity diagramOverviewActivity2 = this.b;
                        com.quizlet.infra.legacysyncengine.managers.d dVar = diagramOverviewActivity2.J;
                        if (dVar == null) {
                            Intrinsics.m("loggedInUserManager");
                            throw null;
                        }
                        com.quizlet.infra.legacysyncengine.net.f fVar = diagramOverviewActivity2.H;
                        if (fVar == null) {
                            Intrinsics.m("syncDispatcher");
                            throw null;
                        }
                        com.quizlet.quizletandroid.managers.audio.h hVar = diagramOverviewActivity2.G;
                        if (hVar == null) {
                            Intrinsics.m("audioManager");
                            throw null;
                        }
                        io.ktor.client.plugins.api.d dVar2 = diagramOverviewActivity2.M;
                        if (dVar2 != null) {
                            return new com.quizlet.quizletandroid.ui.common.adapter.presenter.e(dVar, fVar, hVar, diagramOverviewActivity2, dVar2);
                        }
                        Intrinsics.m("audioPlayFailureManager");
                        throw null;
                    case 4:
                        int i42 = DiagramOverviewActivity.o1;
                        NestedScrollView setpageDiagramBottomSheet = ((C4613q) diagramOverviewActivity.K()).c;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramBottomSheet, "setpageDiagramBottomSheet");
                        return setpageDiagramBottomSheet;
                    case 5:
                        int i52 = DiagramOverviewActivity.o1;
                        StatefulIconFontTextView setpageDiagramDetailsAudio = ((C4613q) diagramOverviewActivity.K()).d;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsAudio, "setpageDiagramDetailsAudio");
                        return setpageDiagramDetailsAudio;
                    case 6:
                        int i62 = DiagramOverviewActivity.o1;
                        ImageView setpageDiagramDetailsClose = ((C4613q) diagramOverviewActivity.K()).e;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsClose, "setpageDiagramDetailsClose");
                        return setpageDiagramDetailsClose;
                    case 7:
                        int i72 = DiagramOverviewActivity.o1;
                        DiagramView setpageDiagramDetailsDiagramView = ((C4613q) diagramOverviewActivity.K()).f;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsDiagramView, "setpageDiagramDetailsDiagramView");
                        return setpageDiagramDetailsDiagramView;
                    case 8:
                        int i82 = DiagramOverviewActivity.o1;
                        QStarIconView setpageDiagramDetailsStar = ((C4613q) diagramOverviewActivity.K()).g;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsStar, "setpageDiagramDetailsStar");
                        return setpageDiagramDetailsStar;
                    case 9:
                        int i92 = DiagramOverviewActivity.o1;
                        QTextView setpageDiagramDetailsTermDefinition = ((C4613q) diagramOverviewActivity.K()).h;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsTermDefinition, "setpageDiagramDetailsTermDefinition");
                        return setpageDiagramDetailsTermDefinition;
                    case 10:
                        int i10 = DiagramOverviewActivity.o1;
                        QTextView setpageDiagramDetailsTermDefinitionLabel = ((C4613q) diagramOverviewActivity.K()).i;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsTermDefinitionLabel, "setpageDiagramDetailsTermDefinitionLabel");
                        return setpageDiagramDetailsTermDefinitionLabel;
                    case 11:
                        int i11 = DiagramOverviewActivity.o1;
                        QTextView setpageDiagramDetailsTermDiagramLabel = ((C4613q) diagramOverviewActivity.K()).j;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsTermDiagramLabel, "setpageDiagramDetailsTermDiagramLabel");
                        return setpageDiagramDetailsTermDiagramLabel;
                    case 12:
                        int i12 = DiagramOverviewActivity.o1;
                        ImageView setpageDiagramDetailsTermImage = ((C4613q) diagramOverviewActivity.K()).k;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsTermImage, "setpageDiagramDetailsTermImage");
                        return setpageDiagramDetailsTermImage;
                    case 13:
                        int i13 = DiagramOverviewActivity.o1;
                        View contentOverlay = ((C4613q) diagramOverviewActivity.K()).b;
                        Intrinsics.checkNotNullExpressionValue(contentOverlay, "contentOverlay");
                        return contentOverlay;
                    case 14:
                        int i14 = DiagramOverviewActivity.o1;
                        QTextView setpageDiagramDetailsTermWord = ((C4613q) diagramOverviewActivity.K()).l;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsTermWord, "setpageDiagramDetailsTermWord");
                        return setpageDiagramDetailsTermWord;
                    case 15:
                        com.quizlet.features.infra.legacyadapter.databinding.f fVar2 = diagramOverviewActivity.B;
                        if (fVar2 == null) {
                            Intrinsics.m("studyModeSettingsToolbarBinding");
                            throw null;
                        }
                        QTextView studyModeSettingsToolbarTitle = (QTextView) fVar2.d;
                        Intrinsics.checkNotNullExpressionValue(studyModeSettingsToolbarTitle, "studyModeSettingsToolbarTitle");
                        return studyModeSettingsToolbarTitle;
                    case 16:
                        com.quizlet.features.infra.legacyadapter.databinding.f fVar3 = diagramOverviewActivity.B;
                        if (fVar3 == null) {
                            Intrinsics.m("studyModeSettingsToolbarBinding");
                            throw null;
                        }
                        FrameLayout studyModeSettingsToolbarUpButton = (FrameLayout) fVar3.c;
                        Intrinsics.checkNotNullExpressionValue(studyModeSettingsToolbarUpButton, "studyModeSettingsToolbarUpButton");
                        return studyModeSettingsToolbarUpButton;
                    default:
                        com.quizlet.features.infra.legacyadapter.databinding.f fVar4 = diagramOverviewActivity.B;
                        if (fVar4 == null) {
                            Intrinsics.m("studyModeSettingsToolbarBinding");
                            throw null;
                        }
                        ImageView studyModeSettingsToolbarUpIcon = (ImageView) fVar4.e;
                        Intrinsics.checkNotNullExpressionValue(studyModeSettingsToolbarUpIcon, "studyModeSettingsToolbarUpIcon");
                        return studyModeSettingsToolbarUpIcon;
                }
            }
        });
        final int i10 = 12;
        this.z = l.b(new Function0(this) { // from class: com.quizlet.quizletandroid.ui.diagramming.a
            public final /* synthetic */ DiagramOverviewActivity b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                DiagramOverviewActivity diagramOverviewActivity = this.b;
                switch (i10) {
                    case 0:
                        int i22 = DiagramOverviewActivity.o1;
                        com.quizlet.infra.legacysyncengine.net.c cVar = diagramOverviewActivity.I;
                        if (cVar == null) {
                            Intrinsics.m("loader");
                            throw null;
                        }
                        long jLongValue = ((Number) diagramOverviewActivity.d1.getValue()).longValue();
                        UserInfoCache userInfoCache = diagramOverviewActivity.F;
                        if (userInfoCache != null) {
                            return new w(cVar, jLongValue, userInfoCache.getPersonId(), false, SortOption.ORIGINAL);
                        }
                        Intrinsics.m("userInfoCache");
                        throw null;
                    case 1:
                        int i32 = DiagramOverviewActivity.o1;
                        return Long.valueOf(diagramOverviewActivity.getIntent().getLongExtra("setId", 0L));
                    case 2:
                        return BottomSheetBehavior.C((NestedScrollView) diagramOverviewActivity.r.getValue());
                    case 3:
                        DiagramOverviewActivity diagramOverviewActivity2 = this.b;
                        com.quizlet.infra.legacysyncengine.managers.d dVar = diagramOverviewActivity2.J;
                        if (dVar == null) {
                            Intrinsics.m("loggedInUserManager");
                            throw null;
                        }
                        com.quizlet.infra.legacysyncengine.net.f fVar = diagramOverviewActivity2.H;
                        if (fVar == null) {
                            Intrinsics.m("syncDispatcher");
                            throw null;
                        }
                        com.quizlet.quizletandroid.managers.audio.h hVar = diagramOverviewActivity2.G;
                        if (hVar == null) {
                            Intrinsics.m("audioManager");
                            throw null;
                        }
                        io.ktor.client.plugins.api.d dVar2 = diagramOverviewActivity2.M;
                        if (dVar2 != null) {
                            return new com.quizlet.quizletandroid.ui.common.adapter.presenter.e(dVar, fVar, hVar, diagramOverviewActivity2, dVar2);
                        }
                        Intrinsics.m("audioPlayFailureManager");
                        throw null;
                    case 4:
                        int i42 = DiagramOverviewActivity.o1;
                        NestedScrollView setpageDiagramBottomSheet = ((C4613q) diagramOverviewActivity.K()).c;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramBottomSheet, "setpageDiagramBottomSheet");
                        return setpageDiagramBottomSheet;
                    case 5:
                        int i52 = DiagramOverviewActivity.o1;
                        StatefulIconFontTextView setpageDiagramDetailsAudio = ((C4613q) diagramOverviewActivity.K()).d;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsAudio, "setpageDiagramDetailsAudio");
                        return setpageDiagramDetailsAudio;
                    case 6:
                        int i62 = DiagramOverviewActivity.o1;
                        ImageView setpageDiagramDetailsClose = ((C4613q) diagramOverviewActivity.K()).e;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsClose, "setpageDiagramDetailsClose");
                        return setpageDiagramDetailsClose;
                    case 7:
                        int i72 = DiagramOverviewActivity.o1;
                        DiagramView setpageDiagramDetailsDiagramView = ((C4613q) diagramOverviewActivity.K()).f;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsDiagramView, "setpageDiagramDetailsDiagramView");
                        return setpageDiagramDetailsDiagramView;
                    case 8:
                        int i82 = DiagramOverviewActivity.o1;
                        QStarIconView setpageDiagramDetailsStar = ((C4613q) diagramOverviewActivity.K()).g;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsStar, "setpageDiagramDetailsStar");
                        return setpageDiagramDetailsStar;
                    case 9:
                        int i92 = DiagramOverviewActivity.o1;
                        QTextView setpageDiagramDetailsTermDefinition = ((C4613q) diagramOverviewActivity.K()).h;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsTermDefinition, "setpageDiagramDetailsTermDefinition");
                        return setpageDiagramDetailsTermDefinition;
                    case 10:
                        int i102 = DiagramOverviewActivity.o1;
                        QTextView setpageDiagramDetailsTermDefinitionLabel = ((C4613q) diagramOverviewActivity.K()).i;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsTermDefinitionLabel, "setpageDiagramDetailsTermDefinitionLabel");
                        return setpageDiagramDetailsTermDefinitionLabel;
                    case 11:
                        int i11 = DiagramOverviewActivity.o1;
                        QTextView setpageDiagramDetailsTermDiagramLabel = ((C4613q) diagramOverviewActivity.K()).j;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsTermDiagramLabel, "setpageDiagramDetailsTermDiagramLabel");
                        return setpageDiagramDetailsTermDiagramLabel;
                    case 12:
                        int i12 = DiagramOverviewActivity.o1;
                        ImageView setpageDiagramDetailsTermImage = ((C4613q) diagramOverviewActivity.K()).k;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsTermImage, "setpageDiagramDetailsTermImage");
                        return setpageDiagramDetailsTermImage;
                    case 13:
                        int i13 = DiagramOverviewActivity.o1;
                        View contentOverlay = ((C4613q) diagramOverviewActivity.K()).b;
                        Intrinsics.checkNotNullExpressionValue(contentOverlay, "contentOverlay");
                        return contentOverlay;
                    case 14:
                        int i14 = DiagramOverviewActivity.o1;
                        QTextView setpageDiagramDetailsTermWord = ((C4613q) diagramOverviewActivity.K()).l;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsTermWord, "setpageDiagramDetailsTermWord");
                        return setpageDiagramDetailsTermWord;
                    case 15:
                        com.quizlet.features.infra.legacyadapter.databinding.f fVar2 = diagramOverviewActivity.B;
                        if (fVar2 == null) {
                            Intrinsics.m("studyModeSettingsToolbarBinding");
                            throw null;
                        }
                        QTextView studyModeSettingsToolbarTitle = (QTextView) fVar2.d;
                        Intrinsics.checkNotNullExpressionValue(studyModeSettingsToolbarTitle, "studyModeSettingsToolbarTitle");
                        return studyModeSettingsToolbarTitle;
                    case 16:
                        com.quizlet.features.infra.legacyadapter.databinding.f fVar3 = diagramOverviewActivity.B;
                        if (fVar3 == null) {
                            Intrinsics.m("studyModeSettingsToolbarBinding");
                            throw null;
                        }
                        FrameLayout studyModeSettingsToolbarUpButton = (FrameLayout) fVar3.c;
                        Intrinsics.checkNotNullExpressionValue(studyModeSettingsToolbarUpButton, "studyModeSettingsToolbarUpButton");
                        return studyModeSettingsToolbarUpButton;
                    default:
                        com.quizlet.features.infra.legacyadapter.databinding.f fVar4 = diagramOverviewActivity.B;
                        if (fVar4 == null) {
                            Intrinsics.m("studyModeSettingsToolbarBinding");
                            throw null;
                        }
                        ImageView studyModeSettingsToolbarUpIcon = (ImageView) fVar4.e;
                        Intrinsics.checkNotNullExpressionValue(studyModeSettingsToolbarUpIcon, "studyModeSettingsToolbarUpIcon");
                        return studyModeSettingsToolbarUpIcon;
                }
            }
        });
        final int i11 = 14;
        this.A = l.b(new Function0(this) { // from class: com.quizlet.quizletandroid.ui.diagramming.a
            public final /* synthetic */ DiagramOverviewActivity b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                DiagramOverviewActivity diagramOverviewActivity = this.b;
                switch (i11) {
                    case 0:
                        int i22 = DiagramOverviewActivity.o1;
                        com.quizlet.infra.legacysyncengine.net.c cVar = diagramOverviewActivity.I;
                        if (cVar == null) {
                            Intrinsics.m("loader");
                            throw null;
                        }
                        long jLongValue = ((Number) diagramOverviewActivity.d1.getValue()).longValue();
                        UserInfoCache userInfoCache = diagramOverviewActivity.F;
                        if (userInfoCache != null) {
                            return new w(cVar, jLongValue, userInfoCache.getPersonId(), false, SortOption.ORIGINAL);
                        }
                        Intrinsics.m("userInfoCache");
                        throw null;
                    case 1:
                        int i32 = DiagramOverviewActivity.o1;
                        return Long.valueOf(diagramOverviewActivity.getIntent().getLongExtra("setId", 0L));
                    case 2:
                        return BottomSheetBehavior.C((NestedScrollView) diagramOverviewActivity.r.getValue());
                    case 3:
                        DiagramOverviewActivity diagramOverviewActivity2 = this.b;
                        com.quizlet.infra.legacysyncengine.managers.d dVar = diagramOverviewActivity2.J;
                        if (dVar == null) {
                            Intrinsics.m("loggedInUserManager");
                            throw null;
                        }
                        com.quizlet.infra.legacysyncengine.net.f fVar = diagramOverviewActivity2.H;
                        if (fVar == null) {
                            Intrinsics.m("syncDispatcher");
                            throw null;
                        }
                        com.quizlet.quizletandroid.managers.audio.h hVar = diagramOverviewActivity2.G;
                        if (hVar == null) {
                            Intrinsics.m("audioManager");
                            throw null;
                        }
                        io.ktor.client.plugins.api.d dVar2 = diagramOverviewActivity2.M;
                        if (dVar2 != null) {
                            return new com.quizlet.quizletandroid.ui.common.adapter.presenter.e(dVar, fVar, hVar, diagramOverviewActivity2, dVar2);
                        }
                        Intrinsics.m("audioPlayFailureManager");
                        throw null;
                    case 4:
                        int i42 = DiagramOverviewActivity.o1;
                        NestedScrollView setpageDiagramBottomSheet = ((C4613q) diagramOverviewActivity.K()).c;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramBottomSheet, "setpageDiagramBottomSheet");
                        return setpageDiagramBottomSheet;
                    case 5:
                        int i52 = DiagramOverviewActivity.o1;
                        StatefulIconFontTextView setpageDiagramDetailsAudio = ((C4613q) diagramOverviewActivity.K()).d;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsAudio, "setpageDiagramDetailsAudio");
                        return setpageDiagramDetailsAudio;
                    case 6:
                        int i62 = DiagramOverviewActivity.o1;
                        ImageView setpageDiagramDetailsClose = ((C4613q) diagramOverviewActivity.K()).e;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsClose, "setpageDiagramDetailsClose");
                        return setpageDiagramDetailsClose;
                    case 7:
                        int i72 = DiagramOverviewActivity.o1;
                        DiagramView setpageDiagramDetailsDiagramView = ((C4613q) diagramOverviewActivity.K()).f;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsDiagramView, "setpageDiagramDetailsDiagramView");
                        return setpageDiagramDetailsDiagramView;
                    case 8:
                        int i82 = DiagramOverviewActivity.o1;
                        QStarIconView setpageDiagramDetailsStar = ((C4613q) diagramOverviewActivity.K()).g;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsStar, "setpageDiagramDetailsStar");
                        return setpageDiagramDetailsStar;
                    case 9:
                        int i92 = DiagramOverviewActivity.o1;
                        QTextView setpageDiagramDetailsTermDefinition = ((C4613q) diagramOverviewActivity.K()).h;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsTermDefinition, "setpageDiagramDetailsTermDefinition");
                        return setpageDiagramDetailsTermDefinition;
                    case 10:
                        int i102 = DiagramOverviewActivity.o1;
                        QTextView setpageDiagramDetailsTermDefinitionLabel = ((C4613q) diagramOverviewActivity.K()).i;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsTermDefinitionLabel, "setpageDiagramDetailsTermDefinitionLabel");
                        return setpageDiagramDetailsTermDefinitionLabel;
                    case 11:
                        int i112 = DiagramOverviewActivity.o1;
                        QTextView setpageDiagramDetailsTermDiagramLabel = ((C4613q) diagramOverviewActivity.K()).j;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsTermDiagramLabel, "setpageDiagramDetailsTermDiagramLabel");
                        return setpageDiagramDetailsTermDiagramLabel;
                    case 12:
                        int i12 = DiagramOverviewActivity.o1;
                        ImageView setpageDiagramDetailsTermImage = ((C4613q) diagramOverviewActivity.K()).k;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsTermImage, "setpageDiagramDetailsTermImage");
                        return setpageDiagramDetailsTermImage;
                    case 13:
                        int i13 = DiagramOverviewActivity.o1;
                        View contentOverlay = ((C4613q) diagramOverviewActivity.K()).b;
                        Intrinsics.checkNotNullExpressionValue(contentOverlay, "contentOverlay");
                        return contentOverlay;
                    case 14:
                        int i14 = DiagramOverviewActivity.o1;
                        QTextView setpageDiagramDetailsTermWord = ((C4613q) diagramOverviewActivity.K()).l;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsTermWord, "setpageDiagramDetailsTermWord");
                        return setpageDiagramDetailsTermWord;
                    case 15:
                        com.quizlet.features.infra.legacyadapter.databinding.f fVar2 = diagramOverviewActivity.B;
                        if (fVar2 == null) {
                            Intrinsics.m("studyModeSettingsToolbarBinding");
                            throw null;
                        }
                        QTextView studyModeSettingsToolbarTitle = (QTextView) fVar2.d;
                        Intrinsics.checkNotNullExpressionValue(studyModeSettingsToolbarTitle, "studyModeSettingsToolbarTitle");
                        return studyModeSettingsToolbarTitle;
                    case 16:
                        com.quizlet.features.infra.legacyadapter.databinding.f fVar3 = diagramOverviewActivity.B;
                        if (fVar3 == null) {
                            Intrinsics.m("studyModeSettingsToolbarBinding");
                            throw null;
                        }
                        FrameLayout studyModeSettingsToolbarUpButton = (FrameLayout) fVar3.c;
                        Intrinsics.checkNotNullExpressionValue(studyModeSettingsToolbarUpButton, "studyModeSettingsToolbarUpButton");
                        return studyModeSettingsToolbarUpButton;
                    default:
                        com.quizlet.features.infra.legacyadapter.databinding.f fVar4 = diagramOverviewActivity.B;
                        if (fVar4 == null) {
                            Intrinsics.m("studyModeSettingsToolbarBinding");
                            throw null;
                        }
                        ImageView studyModeSettingsToolbarUpIcon = (ImageView) fVar4.e;
                        Intrinsics.checkNotNullExpressionValue(studyModeSettingsToolbarUpIcon, "studyModeSettingsToolbarUpIcon");
                        return studyModeSettingsToolbarUpIcon;
                }
            }
        });
        final int i12 = 15;
        this.C = l.b(new Function0(this) { // from class: com.quizlet.quizletandroid.ui.diagramming.a
            public final /* synthetic */ DiagramOverviewActivity b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                DiagramOverviewActivity diagramOverviewActivity = this.b;
                switch (i12) {
                    case 0:
                        int i22 = DiagramOverviewActivity.o1;
                        com.quizlet.infra.legacysyncengine.net.c cVar = diagramOverviewActivity.I;
                        if (cVar == null) {
                            Intrinsics.m("loader");
                            throw null;
                        }
                        long jLongValue = ((Number) diagramOverviewActivity.d1.getValue()).longValue();
                        UserInfoCache userInfoCache = diagramOverviewActivity.F;
                        if (userInfoCache != null) {
                            return new w(cVar, jLongValue, userInfoCache.getPersonId(), false, SortOption.ORIGINAL);
                        }
                        Intrinsics.m("userInfoCache");
                        throw null;
                    case 1:
                        int i32 = DiagramOverviewActivity.o1;
                        return Long.valueOf(diagramOverviewActivity.getIntent().getLongExtra("setId", 0L));
                    case 2:
                        return BottomSheetBehavior.C((NestedScrollView) diagramOverviewActivity.r.getValue());
                    case 3:
                        DiagramOverviewActivity diagramOverviewActivity2 = this.b;
                        com.quizlet.infra.legacysyncengine.managers.d dVar = diagramOverviewActivity2.J;
                        if (dVar == null) {
                            Intrinsics.m("loggedInUserManager");
                            throw null;
                        }
                        com.quizlet.infra.legacysyncengine.net.f fVar = diagramOverviewActivity2.H;
                        if (fVar == null) {
                            Intrinsics.m("syncDispatcher");
                            throw null;
                        }
                        com.quizlet.quizletandroid.managers.audio.h hVar = diagramOverviewActivity2.G;
                        if (hVar == null) {
                            Intrinsics.m("audioManager");
                            throw null;
                        }
                        io.ktor.client.plugins.api.d dVar2 = diagramOverviewActivity2.M;
                        if (dVar2 != null) {
                            return new com.quizlet.quizletandroid.ui.common.adapter.presenter.e(dVar, fVar, hVar, diagramOverviewActivity2, dVar2);
                        }
                        Intrinsics.m("audioPlayFailureManager");
                        throw null;
                    case 4:
                        int i42 = DiagramOverviewActivity.o1;
                        NestedScrollView setpageDiagramBottomSheet = ((C4613q) diagramOverviewActivity.K()).c;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramBottomSheet, "setpageDiagramBottomSheet");
                        return setpageDiagramBottomSheet;
                    case 5:
                        int i52 = DiagramOverviewActivity.o1;
                        StatefulIconFontTextView setpageDiagramDetailsAudio = ((C4613q) diagramOverviewActivity.K()).d;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsAudio, "setpageDiagramDetailsAudio");
                        return setpageDiagramDetailsAudio;
                    case 6:
                        int i62 = DiagramOverviewActivity.o1;
                        ImageView setpageDiagramDetailsClose = ((C4613q) diagramOverviewActivity.K()).e;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsClose, "setpageDiagramDetailsClose");
                        return setpageDiagramDetailsClose;
                    case 7:
                        int i72 = DiagramOverviewActivity.o1;
                        DiagramView setpageDiagramDetailsDiagramView = ((C4613q) diagramOverviewActivity.K()).f;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsDiagramView, "setpageDiagramDetailsDiagramView");
                        return setpageDiagramDetailsDiagramView;
                    case 8:
                        int i82 = DiagramOverviewActivity.o1;
                        QStarIconView setpageDiagramDetailsStar = ((C4613q) diagramOverviewActivity.K()).g;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsStar, "setpageDiagramDetailsStar");
                        return setpageDiagramDetailsStar;
                    case 9:
                        int i92 = DiagramOverviewActivity.o1;
                        QTextView setpageDiagramDetailsTermDefinition = ((C4613q) diagramOverviewActivity.K()).h;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsTermDefinition, "setpageDiagramDetailsTermDefinition");
                        return setpageDiagramDetailsTermDefinition;
                    case 10:
                        int i102 = DiagramOverviewActivity.o1;
                        QTextView setpageDiagramDetailsTermDefinitionLabel = ((C4613q) diagramOverviewActivity.K()).i;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsTermDefinitionLabel, "setpageDiagramDetailsTermDefinitionLabel");
                        return setpageDiagramDetailsTermDefinitionLabel;
                    case 11:
                        int i112 = DiagramOverviewActivity.o1;
                        QTextView setpageDiagramDetailsTermDiagramLabel = ((C4613q) diagramOverviewActivity.K()).j;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsTermDiagramLabel, "setpageDiagramDetailsTermDiagramLabel");
                        return setpageDiagramDetailsTermDiagramLabel;
                    case 12:
                        int i122 = DiagramOverviewActivity.o1;
                        ImageView setpageDiagramDetailsTermImage = ((C4613q) diagramOverviewActivity.K()).k;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsTermImage, "setpageDiagramDetailsTermImage");
                        return setpageDiagramDetailsTermImage;
                    case 13:
                        int i13 = DiagramOverviewActivity.o1;
                        View contentOverlay = ((C4613q) diagramOverviewActivity.K()).b;
                        Intrinsics.checkNotNullExpressionValue(contentOverlay, "contentOverlay");
                        return contentOverlay;
                    case 14:
                        int i14 = DiagramOverviewActivity.o1;
                        QTextView setpageDiagramDetailsTermWord = ((C4613q) diagramOverviewActivity.K()).l;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsTermWord, "setpageDiagramDetailsTermWord");
                        return setpageDiagramDetailsTermWord;
                    case 15:
                        com.quizlet.features.infra.legacyadapter.databinding.f fVar2 = diagramOverviewActivity.B;
                        if (fVar2 == null) {
                            Intrinsics.m("studyModeSettingsToolbarBinding");
                            throw null;
                        }
                        QTextView studyModeSettingsToolbarTitle = (QTextView) fVar2.d;
                        Intrinsics.checkNotNullExpressionValue(studyModeSettingsToolbarTitle, "studyModeSettingsToolbarTitle");
                        return studyModeSettingsToolbarTitle;
                    case 16:
                        com.quizlet.features.infra.legacyadapter.databinding.f fVar3 = diagramOverviewActivity.B;
                        if (fVar3 == null) {
                            Intrinsics.m("studyModeSettingsToolbarBinding");
                            throw null;
                        }
                        FrameLayout studyModeSettingsToolbarUpButton = (FrameLayout) fVar3.c;
                        Intrinsics.checkNotNullExpressionValue(studyModeSettingsToolbarUpButton, "studyModeSettingsToolbarUpButton");
                        return studyModeSettingsToolbarUpButton;
                    default:
                        com.quizlet.features.infra.legacyadapter.databinding.f fVar4 = diagramOverviewActivity.B;
                        if (fVar4 == null) {
                            Intrinsics.m("studyModeSettingsToolbarBinding");
                            throw null;
                        }
                        ImageView studyModeSettingsToolbarUpIcon = (ImageView) fVar4.e;
                        Intrinsics.checkNotNullExpressionValue(studyModeSettingsToolbarUpIcon, "studyModeSettingsToolbarUpIcon");
                        return studyModeSettingsToolbarUpIcon;
                }
            }
        });
        final int i13 = 16;
        this.D = l.b(new Function0(this) { // from class: com.quizlet.quizletandroid.ui.diagramming.a
            public final /* synthetic */ DiagramOverviewActivity b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                DiagramOverviewActivity diagramOverviewActivity = this.b;
                switch (i13) {
                    case 0:
                        int i22 = DiagramOverviewActivity.o1;
                        com.quizlet.infra.legacysyncengine.net.c cVar = diagramOverviewActivity.I;
                        if (cVar == null) {
                            Intrinsics.m("loader");
                            throw null;
                        }
                        long jLongValue = ((Number) diagramOverviewActivity.d1.getValue()).longValue();
                        UserInfoCache userInfoCache = diagramOverviewActivity.F;
                        if (userInfoCache != null) {
                            return new w(cVar, jLongValue, userInfoCache.getPersonId(), false, SortOption.ORIGINAL);
                        }
                        Intrinsics.m("userInfoCache");
                        throw null;
                    case 1:
                        int i32 = DiagramOverviewActivity.o1;
                        return Long.valueOf(diagramOverviewActivity.getIntent().getLongExtra("setId", 0L));
                    case 2:
                        return BottomSheetBehavior.C((NestedScrollView) diagramOverviewActivity.r.getValue());
                    case 3:
                        DiagramOverviewActivity diagramOverviewActivity2 = this.b;
                        com.quizlet.infra.legacysyncengine.managers.d dVar = diagramOverviewActivity2.J;
                        if (dVar == null) {
                            Intrinsics.m("loggedInUserManager");
                            throw null;
                        }
                        com.quizlet.infra.legacysyncengine.net.f fVar = diagramOverviewActivity2.H;
                        if (fVar == null) {
                            Intrinsics.m("syncDispatcher");
                            throw null;
                        }
                        com.quizlet.quizletandroid.managers.audio.h hVar = diagramOverviewActivity2.G;
                        if (hVar == null) {
                            Intrinsics.m("audioManager");
                            throw null;
                        }
                        io.ktor.client.plugins.api.d dVar2 = diagramOverviewActivity2.M;
                        if (dVar2 != null) {
                            return new com.quizlet.quizletandroid.ui.common.adapter.presenter.e(dVar, fVar, hVar, diagramOverviewActivity2, dVar2);
                        }
                        Intrinsics.m("audioPlayFailureManager");
                        throw null;
                    case 4:
                        int i42 = DiagramOverviewActivity.o1;
                        NestedScrollView setpageDiagramBottomSheet = ((C4613q) diagramOverviewActivity.K()).c;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramBottomSheet, "setpageDiagramBottomSheet");
                        return setpageDiagramBottomSheet;
                    case 5:
                        int i52 = DiagramOverviewActivity.o1;
                        StatefulIconFontTextView setpageDiagramDetailsAudio = ((C4613q) diagramOverviewActivity.K()).d;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsAudio, "setpageDiagramDetailsAudio");
                        return setpageDiagramDetailsAudio;
                    case 6:
                        int i62 = DiagramOverviewActivity.o1;
                        ImageView setpageDiagramDetailsClose = ((C4613q) diagramOverviewActivity.K()).e;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsClose, "setpageDiagramDetailsClose");
                        return setpageDiagramDetailsClose;
                    case 7:
                        int i72 = DiagramOverviewActivity.o1;
                        DiagramView setpageDiagramDetailsDiagramView = ((C4613q) diagramOverviewActivity.K()).f;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsDiagramView, "setpageDiagramDetailsDiagramView");
                        return setpageDiagramDetailsDiagramView;
                    case 8:
                        int i82 = DiagramOverviewActivity.o1;
                        QStarIconView setpageDiagramDetailsStar = ((C4613q) diagramOverviewActivity.K()).g;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsStar, "setpageDiagramDetailsStar");
                        return setpageDiagramDetailsStar;
                    case 9:
                        int i92 = DiagramOverviewActivity.o1;
                        QTextView setpageDiagramDetailsTermDefinition = ((C4613q) diagramOverviewActivity.K()).h;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsTermDefinition, "setpageDiagramDetailsTermDefinition");
                        return setpageDiagramDetailsTermDefinition;
                    case 10:
                        int i102 = DiagramOverviewActivity.o1;
                        QTextView setpageDiagramDetailsTermDefinitionLabel = ((C4613q) diagramOverviewActivity.K()).i;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsTermDefinitionLabel, "setpageDiagramDetailsTermDefinitionLabel");
                        return setpageDiagramDetailsTermDefinitionLabel;
                    case 11:
                        int i112 = DiagramOverviewActivity.o1;
                        QTextView setpageDiagramDetailsTermDiagramLabel = ((C4613q) diagramOverviewActivity.K()).j;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsTermDiagramLabel, "setpageDiagramDetailsTermDiagramLabel");
                        return setpageDiagramDetailsTermDiagramLabel;
                    case 12:
                        int i122 = DiagramOverviewActivity.o1;
                        ImageView setpageDiagramDetailsTermImage = ((C4613q) diagramOverviewActivity.K()).k;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsTermImage, "setpageDiagramDetailsTermImage");
                        return setpageDiagramDetailsTermImage;
                    case 13:
                        int i132 = DiagramOverviewActivity.o1;
                        View contentOverlay = ((C4613q) diagramOverviewActivity.K()).b;
                        Intrinsics.checkNotNullExpressionValue(contentOverlay, "contentOverlay");
                        return contentOverlay;
                    case 14:
                        int i14 = DiagramOverviewActivity.o1;
                        QTextView setpageDiagramDetailsTermWord = ((C4613q) diagramOverviewActivity.K()).l;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsTermWord, "setpageDiagramDetailsTermWord");
                        return setpageDiagramDetailsTermWord;
                    case 15:
                        com.quizlet.features.infra.legacyadapter.databinding.f fVar2 = diagramOverviewActivity.B;
                        if (fVar2 == null) {
                            Intrinsics.m("studyModeSettingsToolbarBinding");
                            throw null;
                        }
                        QTextView studyModeSettingsToolbarTitle = (QTextView) fVar2.d;
                        Intrinsics.checkNotNullExpressionValue(studyModeSettingsToolbarTitle, "studyModeSettingsToolbarTitle");
                        return studyModeSettingsToolbarTitle;
                    case 16:
                        com.quizlet.features.infra.legacyadapter.databinding.f fVar3 = diagramOverviewActivity.B;
                        if (fVar3 == null) {
                            Intrinsics.m("studyModeSettingsToolbarBinding");
                            throw null;
                        }
                        FrameLayout studyModeSettingsToolbarUpButton = (FrameLayout) fVar3.c;
                        Intrinsics.checkNotNullExpressionValue(studyModeSettingsToolbarUpButton, "studyModeSettingsToolbarUpButton");
                        return studyModeSettingsToolbarUpButton;
                    default:
                        com.quizlet.features.infra.legacyadapter.databinding.f fVar4 = diagramOverviewActivity.B;
                        if (fVar4 == null) {
                            Intrinsics.m("studyModeSettingsToolbarBinding");
                            throw null;
                        }
                        ImageView studyModeSettingsToolbarUpIcon = (ImageView) fVar4.e;
                        Intrinsics.checkNotNullExpressionValue(studyModeSettingsToolbarUpIcon, "studyModeSettingsToolbarUpIcon");
                        return studyModeSettingsToolbarUpIcon;
                }
            }
        });
        final int i14 = 17;
        this.E = l.b(new Function0(this) { // from class: com.quizlet.quizletandroid.ui.diagramming.a
            public final /* synthetic */ DiagramOverviewActivity b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                DiagramOverviewActivity diagramOverviewActivity = this.b;
                switch (i14) {
                    case 0:
                        int i22 = DiagramOverviewActivity.o1;
                        com.quizlet.infra.legacysyncengine.net.c cVar = diagramOverviewActivity.I;
                        if (cVar == null) {
                            Intrinsics.m("loader");
                            throw null;
                        }
                        long jLongValue = ((Number) diagramOverviewActivity.d1.getValue()).longValue();
                        UserInfoCache userInfoCache = diagramOverviewActivity.F;
                        if (userInfoCache != null) {
                            return new w(cVar, jLongValue, userInfoCache.getPersonId(), false, SortOption.ORIGINAL);
                        }
                        Intrinsics.m("userInfoCache");
                        throw null;
                    case 1:
                        int i32 = DiagramOverviewActivity.o1;
                        return Long.valueOf(diagramOverviewActivity.getIntent().getLongExtra("setId", 0L));
                    case 2:
                        return BottomSheetBehavior.C((NestedScrollView) diagramOverviewActivity.r.getValue());
                    case 3:
                        DiagramOverviewActivity diagramOverviewActivity2 = this.b;
                        com.quizlet.infra.legacysyncengine.managers.d dVar = diagramOverviewActivity2.J;
                        if (dVar == null) {
                            Intrinsics.m("loggedInUserManager");
                            throw null;
                        }
                        com.quizlet.infra.legacysyncengine.net.f fVar = diagramOverviewActivity2.H;
                        if (fVar == null) {
                            Intrinsics.m("syncDispatcher");
                            throw null;
                        }
                        com.quizlet.quizletandroid.managers.audio.h hVar = diagramOverviewActivity2.G;
                        if (hVar == null) {
                            Intrinsics.m("audioManager");
                            throw null;
                        }
                        io.ktor.client.plugins.api.d dVar2 = diagramOverviewActivity2.M;
                        if (dVar2 != null) {
                            return new com.quizlet.quizletandroid.ui.common.adapter.presenter.e(dVar, fVar, hVar, diagramOverviewActivity2, dVar2);
                        }
                        Intrinsics.m("audioPlayFailureManager");
                        throw null;
                    case 4:
                        int i42 = DiagramOverviewActivity.o1;
                        NestedScrollView setpageDiagramBottomSheet = ((C4613q) diagramOverviewActivity.K()).c;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramBottomSheet, "setpageDiagramBottomSheet");
                        return setpageDiagramBottomSheet;
                    case 5:
                        int i52 = DiagramOverviewActivity.o1;
                        StatefulIconFontTextView setpageDiagramDetailsAudio = ((C4613q) diagramOverviewActivity.K()).d;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsAudio, "setpageDiagramDetailsAudio");
                        return setpageDiagramDetailsAudio;
                    case 6:
                        int i62 = DiagramOverviewActivity.o1;
                        ImageView setpageDiagramDetailsClose = ((C4613q) diagramOverviewActivity.K()).e;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsClose, "setpageDiagramDetailsClose");
                        return setpageDiagramDetailsClose;
                    case 7:
                        int i72 = DiagramOverviewActivity.o1;
                        DiagramView setpageDiagramDetailsDiagramView = ((C4613q) diagramOverviewActivity.K()).f;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsDiagramView, "setpageDiagramDetailsDiagramView");
                        return setpageDiagramDetailsDiagramView;
                    case 8:
                        int i82 = DiagramOverviewActivity.o1;
                        QStarIconView setpageDiagramDetailsStar = ((C4613q) diagramOverviewActivity.K()).g;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsStar, "setpageDiagramDetailsStar");
                        return setpageDiagramDetailsStar;
                    case 9:
                        int i92 = DiagramOverviewActivity.o1;
                        QTextView setpageDiagramDetailsTermDefinition = ((C4613q) diagramOverviewActivity.K()).h;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsTermDefinition, "setpageDiagramDetailsTermDefinition");
                        return setpageDiagramDetailsTermDefinition;
                    case 10:
                        int i102 = DiagramOverviewActivity.o1;
                        QTextView setpageDiagramDetailsTermDefinitionLabel = ((C4613q) diagramOverviewActivity.K()).i;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsTermDefinitionLabel, "setpageDiagramDetailsTermDefinitionLabel");
                        return setpageDiagramDetailsTermDefinitionLabel;
                    case 11:
                        int i112 = DiagramOverviewActivity.o1;
                        QTextView setpageDiagramDetailsTermDiagramLabel = ((C4613q) diagramOverviewActivity.K()).j;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsTermDiagramLabel, "setpageDiagramDetailsTermDiagramLabel");
                        return setpageDiagramDetailsTermDiagramLabel;
                    case 12:
                        int i122 = DiagramOverviewActivity.o1;
                        ImageView setpageDiagramDetailsTermImage = ((C4613q) diagramOverviewActivity.K()).k;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsTermImage, "setpageDiagramDetailsTermImage");
                        return setpageDiagramDetailsTermImage;
                    case 13:
                        int i132 = DiagramOverviewActivity.o1;
                        View contentOverlay = ((C4613q) diagramOverviewActivity.K()).b;
                        Intrinsics.checkNotNullExpressionValue(contentOverlay, "contentOverlay");
                        return contentOverlay;
                    case 14:
                        int i142 = DiagramOverviewActivity.o1;
                        QTextView setpageDiagramDetailsTermWord = ((C4613q) diagramOverviewActivity.K()).l;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsTermWord, "setpageDiagramDetailsTermWord");
                        return setpageDiagramDetailsTermWord;
                    case 15:
                        com.quizlet.features.infra.legacyadapter.databinding.f fVar2 = diagramOverviewActivity.B;
                        if (fVar2 == null) {
                            Intrinsics.m("studyModeSettingsToolbarBinding");
                            throw null;
                        }
                        QTextView studyModeSettingsToolbarTitle = (QTextView) fVar2.d;
                        Intrinsics.checkNotNullExpressionValue(studyModeSettingsToolbarTitle, "studyModeSettingsToolbarTitle");
                        return studyModeSettingsToolbarTitle;
                    case 16:
                        com.quizlet.features.infra.legacyadapter.databinding.f fVar3 = diagramOverviewActivity.B;
                        if (fVar3 == null) {
                            Intrinsics.m("studyModeSettingsToolbarBinding");
                            throw null;
                        }
                        FrameLayout studyModeSettingsToolbarUpButton = (FrameLayout) fVar3.c;
                        Intrinsics.checkNotNullExpressionValue(studyModeSettingsToolbarUpButton, "studyModeSettingsToolbarUpButton");
                        return studyModeSettingsToolbarUpButton;
                    default:
                        com.quizlet.features.infra.legacyadapter.databinding.f fVar4 = diagramOverviewActivity.B;
                        if (fVar4 == null) {
                            Intrinsics.m("studyModeSettingsToolbarBinding");
                            throw null;
                        }
                        ImageView studyModeSettingsToolbarUpIcon = (ImageView) fVar4.e;
                        Intrinsics.checkNotNullExpressionValue(studyModeSettingsToolbarUpIcon, "studyModeSettingsToolbarUpIcon");
                        return studyModeSettingsToolbarUpIcon;
                }
            }
        });
        this.V = Z.f("create(...)");
        this.W = Z.f("create(...)");
        this.X = Z.f("create(...)");
        io.reactivex.rxjava3.subjects.d dVarZ = io.reactivex.rxjava3.subjects.d.z();
        Intrinsics.checkNotNullExpressionValue(dVarZ, "create(...)");
        this.Y = dVarZ;
        final int i15 = 0;
        this.c1 = l.b(new Function0(this) { // from class: com.quizlet.quizletandroid.ui.diagramming.a
            public final /* synthetic */ DiagramOverviewActivity b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                DiagramOverviewActivity diagramOverviewActivity = this.b;
                switch (i15) {
                    case 0:
                        int i22 = DiagramOverviewActivity.o1;
                        com.quizlet.infra.legacysyncengine.net.c cVar = diagramOverviewActivity.I;
                        if (cVar == null) {
                            Intrinsics.m("loader");
                            throw null;
                        }
                        long jLongValue = ((Number) diagramOverviewActivity.d1.getValue()).longValue();
                        UserInfoCache userInfoCache = diagramOverviewActivity.F;
                        if (userInfoCache != null) {
                            return new w(cVar, jLongValue, userInfoCache.getPersonId(), false, SortOption.ORIGINAL);
                        }
                        Intrinsics.m("userInfoCache");
                        throw null;
                    case 1:
                        int i32 = DiagramOverviewActivity.o1;
                        return Long.valueOf(diagramOverviewActivity.getIntent().getLongExtra("setId", 0L));
                    case 2:
                        return BottomSheetBehavior.C((NestedScrollView) diagramOverviewActivity.r.getValue());
                    case 3:
                        DiagramOverviewActivity diagramOverviewActivity2 = this.b;
                        com.quizlet.infra.legacysyncengine.managers.d dVar = diagramOverviewActivity2.J;
                        if (dVar == null) {
                            Intrinsics.m("loggedInUserManager");
                            throw null;
                        }
                        com.quizlet.infra.legacysyncengine.net.f fVar = diagramOverviewActivity2.H;
                        if (fVar == null) {
                            Intrinsics.m("syncDispatcher");
                            throw null;
                        }
                        com.quizlet.quizletandroid.managers.audio.h hVar = diagramOverviewActivity2.G;
                        if (hVar == null) {
                            Intrinsics.m("audioManager");
                            throw null;
                        }
                        io.ktor.client.plugins.api.d dVar2 = diagramOverviewActivity2.M;
                        if (dVar2 != null) {
                            return new com.quizlet.quizletandroid.ui.common.adapter.presenter.e(dVar, fVar, hVar, diagramOverviewActivity2, dVar2);
                        }
                        Intrinsics.m("audioPlayFailureManager");
                        throw null;
                    case 4:
                        int i42 = DiagramOverviewActivity.o1;
                        NestedScrollView setpageDiagramBottomSheet = ((C4613q) diagramOverviewActivity.K()).c;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramBottomSheet, "setpageDiagramBottomSheet");
                        return setpageDiagramBottomSheet;
                    case 5:
                        int i52 = DiagramOverviewActivity.o1;
                        StatefulIconFontTextView setpageDiagramDetailsAudio = ((C4613q) diagramOverviewActivity.K()).d;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsAudio, "setpageDiagramDetailsAudio");
                        return setpageDiagramDetailsAudio;
                    case 6:
                        int i62 = DiagramOverviewActivity.o1;
                        ImageView setpageDiagramDetailsClose = ((C4613q) diagramOverviewActivity.K()).e;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsClose, "setpageDiagramDetailsClose");
                        return setpageDiagramDetailsClose;
                    case 7:
                        int i72 = DiagramOverviewActivity.o1;
                        DiagramView setpageDiagramDetailsDiagramView = ((C4613q) diagramOverviewActivity.K()).f;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsDiagramView, "setpageDiagramDetailsDiagramView");
                        return setpageDiagramDetailsDiagramView;
                    case 8:
                        int i82 = DiagramOverviewActivity.o1;
                        QStarIconView setpageDiagramDetailsStar = ((C4613q) diagramOverviewActivity.K()).g;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsStar, "setpageDiagramDetailsStar");
                        return setpageDiagramDetailsStar;
                    case 9:
                        int i92 = DiagramOverviewActivity.o1;
                        QTextView setpageDiagramDetailsTermDefinition = ((C4613q) diagramOverviewActivity.K()).h;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsTermDefinition, "setpageDiagramDetailsTermDefinition");
                        return setpageDiagramDetailsTermDefinition;
                    case 10:
                        int i102 = DiagramOverviewActivity.o1;
                        QTextView setpageDiagramDetailsTermDefinitionLabel = ((C4613q) diagramOverviewActivity.K()).i;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsTermDefinitionLabel, "setpageDiagramDetailsTermDefinitionLabel");
                        return setpageDiagramDetailsTermDefinitionLabel;
                    case 11:
                        int i112 = DiagramOverviewActivity.o1;
                        QTextView setpageDiagramDetailsTermDiagramLabel = ((C4613q) diagramOverviewActivity.K()).j;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsTermDiagramLabel, "setpageDiagramDetailsTermDiagramLabel");
                        return setpageDiagramDetailsTermDiagramLabel;
                    case 12:
                        int i122 = DiagramOverviewActivity.o1;
                        ImageView setpageDiagramDetailsTermImage = ((C4613q) diagramOverviewActivity.K()).k;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsTermImage, "setpageDiagramDetailsTermImage");
                        return setpageDiagramDetailsTermImage;
                    case 13:
                        int i132 = DiagramOverviewActivity.o1;
                        View contentOverlay = ((C4613q) diagramOverviewActivity.K()).b;
                        Intrinsics.checkNotNullExpressionValue(contentOverlay, "contentOverlay");
                        return contentOverlay;
                    case 14:
                        int i142 = DiagramOverviewActivity.o1;
                        QTextView setpageDiagramDetailsTermWord = ((C4613q) diagramOverviewActivity.K()).l;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsTermWord, "setpageDiagramDetailsTermWord");
                        return setpageDiagramDetailsTermWord;
                    case 15:
                        com.quizlet.features.infra.legacyadapter.databinding.f fVar2 = diagramOverviewActivity.B;
                        if (fVar2 == null) {
                            Intrinsics.m("studyModeSettingsToolbarBinding");
                            throw null;
                        }
                        QTextView studyModeSettingsToolbarTitle = (QTextView) fVar2.d;
                        Intrinsics.checkNotNullExpressionValue(studyModeSettingsToolbarTitle, "studyModeSettingsToolbarTitle");
                        return studyModeSettingsToolbarTitle;
                    case 16:
                        com.quizlet.features.infra.legacyadapter.databinding.f fVar3 = diagramOverviewActivity.B;
                        if (fVar3 == null) {
                            Intrinsics.m("studyModeSettingsToolbarBinding");
                            throw null;
                        }
                        FrameLayout studyModeSettingsToolbarUpButton = (FrameLayout) fVar3.c;
                        Intrinsics.checkNotNullExpressionValue(studyModeSettingsToolbarUpButton, "studyModeSettingsToolbarUpButton");
                        return studyModeSettingsToolbarUpButton;
                    default:
                        com.quizlet.features.infra.legacyadapter.databinding.f fVar4 = diagramOverviewActivity.B;
                        if (fVar4 == null) {
                            Intrinsics.m("studyModeSettingsToolbarBinding");
                            throw null;
                        }
                        ImageView studyModeSettingsToolbarUpIcon = (ImageView) fVar4.e;
                        Intrinsics.checkNotNullExpressionValue(studyModeSettingsToolbarUpIcon, "studyModeSettingsToolbarUpIcon");
                        return studyModeSettingsToolbarUpIcon;
                }
            }
        });
        final int i16 = 1;
        this.d1 = l.b(new Function0(this) { // from class: com.quizlet.quizletandroid.ui.diagramming.a
            public final /* synthetic */ DiagramOverviewActivity b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                DiagramOverviewActivity diagramOverviewActivity = this.b;
                switch (i16) {
                    case 0:
                        int i22 = DiagramOverviewActivity.o1;
                        com.quizlet.infra.legacysyncengine.net.c cVar = diagramOverviewActivity.I;
                        if (cVar == null) {
                            Intrinsics.m("loader");
                            throw null;
                        }
                        long jLongValue = ((Number) diagramOverviewActivity.d1.getValue()).longValue();
                        UserInfoCache userInfoCache = diagramOverviewActivity.F;
                        if (userInfoCache != null) {
                            return new w(cVar, jLongValue, userInfoCache.getPersonId(), false, SortOption.ORIGINAL);
                        }
                        Intrinsics.m("userInfoCache");
                        throw null;
                    case 1:
                        int i32 = DiagramOverviewActivity.o1;
                        return Long.valueOf(diagramOverviewActivity.getIntent().getLongExtra("setId", 0L));
                    case 2:
                        return BottomSheetBehavior.C((NestedScrollView) diagramOverviewActivity.r.getValue());
                    case 3:
                        DiagramOverviewActivity diagramOverviewActivity2 = this.b;
                        com.quizlet.infra.legacysyncengine.managers.d dVar = diagramOverviewActivity2.J;
                        if (dVar == null) {
                            Intrinsics.m("loggedInUserManager");
                            throw null;
                        }
                        com.quizlet.infra.legacysyncengine.net.f fVar = diagramOverviewActivity2.H;
                        if (fVar == null) {
                            Intrinsics.m("syncDispatcher");
                            throw null;
                        }
                        com.quizlet.quizletandroid.managers.audio.h hVar = diagramOverviewActivity2.G;
                        if (hVar == null) {
                            Intrinsics.m("audioManager");
                            throw null;
                        }
                        io.ktor.client.plugins.api.d dVar2 = diagramOverviewActivity2.M;
                        if (dVar2 != null) {
                            return new com.quizlet.quizletandroid.ui.common.adapter.presenter.e(dVar, fVar, hVar, diagramOverviewActivity2, dVar2);
                        }
                        Intrinsics.m("audioPlayFailureManager");
                        throw null;
                    case 4:
                        int i42 = DiagramOverviewActivity.o1;
                        NestedScrollView setpageDiagramBottomSheet = ((C4613q) diagramOverviewActivity.K()).c;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramBottomSheet, "setpageDiagramBottomSheet");
                        return setpageDiagramBottomSheet;
                    case 5:
                        int i52 = DiagramOverviewActivity.o1;
                        StatefulIconFontTextView setpageDiagramDetailsAudio = ((C4613q) diagramOverviewActivity.K()).d;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsAudio, "setpageDiagramDetailsAudio");
                        return setpageDiagramDetailsAudio;
                    case 6:
                        int i62 = DiagramOverviewActivity.o1;
                        ImageView setpageDiagramDetailsClose = ((C4613q) diagramOverviewActivity.K()).e;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsClose, "setpageDiagramDetailsClose");
                        return setpageDiagramDetailsClose;
                    case 7:
                        int i72 = DiagramOverviewActivity.o1;
                        DiagramView setpageDiagramDetailsDiagramView = ((C4613q) diagramOverviewActivity.K()).f;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsDiagramView, "setpageDiagramDetailsDiagramView");
                        return setpageDiagramDetailsDiagramView;
                    case 8:
                        int i82 = DiagramOverviewActivity.o1;
                        QStarIconView setpageDiagramDetailsStar = ((C4613q) diagramOverviewActivity.K()).g;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsStar, "setpageDiagramDetailsStar");
                        return setpageDiagramDetailsStar;
                    case 9:
                        int i92 = DiagramOverviewActivity.o1;
                        QTextView setpageDiagramDetailsTermDefinition = ((C4613q) diagramOverviewActivity.K()).h;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsTermDefinition, "setpageDiagramDetailsTermDefinition");
                        return setpageDiagramDetailsTermDefinition;
                    case 10:
                        int i102 = DiagramOverviewActivity.o1;
                        QTextView setpageDiagramDetailsTermDefinitionLabel = ((C4613q) diagramOverviewActivity.K()).i;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsTermDefinitionLabel, "setpageDiagramDetailsTermDefinitionLabel");
                        return setpageDiagramDetailsTermDefinitionLabel;
                    case 11:
                        int i112 = DiagramOverviewActivity.o1;
                        QTextView setpageDiagramDetailsTermDiagramLabel = ((C4613q) diagramOverviewActivity.K()).j;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsTermDiagramLabel, "setpageDiagramDetailsTermDiagramLabel");
                        return setpageDiagramDetailsTermDiagramLabel;
                    case 12:
                        int i122 = DiagramOverviewActivity.o1;
                        ImageView setpageDiagramDetailsTermImage = ((C4613q) diagramOverviewActivity.K()).k;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsTermImage, "setpageDiagramDetailsTermImage");
                        return setpageDiagramDetailsTermImage;
                    case 13:
                        int i132 = DiagramOverviewActivity.o1;
                        View contentOverlay = ((C4613q) diagramOverviewActivity.K()).b;
                        Intrinsics.checkNotNullExpressionValue(contentOverlay, "contentOverlay");
                        return contentOverlay;
                    case 14:
                        int i142 = DiagramOverviewActivity.o1;
                        QTextView setpageDiagramDetailsTermWord = ((C4613q) diagramOverviewActivity.K()).l;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsTermWord, "setpageDiagramDetailsTermWord");
                        return setpageDiagramDetailsTermWord;
                    case 15:
                        com.quizlet.features.infra.legacyadapter.databinding.f fVar2 = diagramOverviewActivity.B;
                        if (fVar2 == null) {
                            Intrinsics.m("studyModeSettingsToolbarBinding");
                            throw null;
                        }
                        QTextView studyModeSettingsToolbarTitle = (QTextView) fVar2.d;
                        Intrinsics.checkNotNullExpressionValue(studyModeSettingsToolbarTitle, "studyModeSettingsToolbarTitle");
                        return studyModeSettingsToolbarTitle;
                    case 16:
                        com.quizlet.features.infra.legacyadapter.databinding.f fVar3 = diagramOverviewActivity.B;
                        if (fVar3 == null) {
                            Intrinsics.m("studyModeSettingsToolbarBinding");
                            throw null;
                        }
                        FrameLayout studyModeSettingsToolbarUpButton = (FrameLayout) fVar3.c;
                        Intrinsics.checkNotNullExpressionValue(studyModeSettingsToolbarUpButton, "studyModeSettingsToolbarUpButton");
                        return studyModeSettingsToolbarUpButton;
                    default:
                        com.quizlet.features.infra.legacyadapter.databinding.f fVar4 = diagramOverviewActivity.B;
                        if (fVar4 == null) {
                            Intrinsics.m("studyModeSettingsToolbarBinding");
                            throw null;
                        }
                        ImageView studyModeSettingsToolbarUpIcon = (ImageView) fVar4.e;
                        Intrinsics.checkNotNullExpressionValue(studyModeSettingsToolbarUpIcon, "studyModeSettingsToolbarUpIcon");
                        return studyModeSettingsToolbarUpIcon;
                }
            }
        });
        final int i17 = 2;
        this.e1 = l.b(new Function0(this) { // from class: com.quizlet.quizletandroid.ui.diagramming.a
            public final /* synthetic */ DiagramOverviewActivity b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                DiagramOverviewActivity diagramOverviewActivity = this.b;
                switch (i17) {
                    case 0:
                        int i22 = DiagramOverviewActivity.o1;
                        com.quizlet.infra.legacysyncengine.net.c cVar = diagramOverviewActivity.I;
                        if (cVar == null) {
                            Intrinsics.m("loader");
                            throw null;
                        }
                        long jLongValue = ((Number) diagramOverviewActivity.d1.getValue()).longValue();
                        UserInfoCache userInfoCache = diagramOverviewActivity.F;
                        if (userInfoCache != null) {
                            return new w(cVar, jLongValue, userInfoCache.getPersonId(), false, SortOption.ORIGINAL);
                        }
                        Intrinsics.m("userInfoCache");
                        throw null;
                    case 1:
                        int i32 = DiagramOverviewActivity.o1;
                        return Long.valueOf(diagramOverviewActivity.getIntent().getLongExtra("setId", 0L));
                    case 2:
                        return BottomSheetBehavior.C((NestedScrollView) diagramOverviewActivity.r.getValue());
                    case 3:
                        DiagramOverviewActivity diagramOverviewActivity2 = this.b;
                        com.quizlet.infra.legacysyncengine.managers.d dVar = diagramOverviewActivity2.J;
                        if (dVar == null) {
                            Intrinsics.m("loggedInUserManager");
                            throw null;
                        }
                        com.quizlet.infra.legacysyncengine.net.f fVar = diagramOverviewActivity2.H;
                        if (fVar == null) {
                            Intrinsics.m("syncDispatcher");
                            throw null;
                        }
                        com.quizlet.quizletandroid.managers.audio.h hVar = diagramOverviewActivity2.G;
                        if (hVar == null) {
                            Intrinsics.m("audioManager");
                            throw null;
                        }
                        io.ktor.client.plugins.api.d dVar2 = diagramOverviewActivity2.M;
                        if (dVar2 != null) {
                            return new com.quizlet.quizletandroid.ui.common.adapter.presenter.e(dVar, fVar, hVar, diagramOverviewActivity2, dVar2);
                        }
                        Intrinsics.m("audioPlayFailureManager");
                        throw null;
                    case 4:
                        int i42 = DiagramOverviewActivity.o1;
                        NestedScrollView setpageDiagramBottomSheet = ((C4613q) diagramOverviewActivity.K()).c;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramBottomSheet, "setpageDiagramBottomSheet");
                        return setpageDiagramBottomSheet;
                    case 5:
                        int i52 = DiagramOverviewActivity.o1;
                        StatefulIconFontTextView setpageDiagramDetailsAudio = ((C4613q) diagramOverviewActivity.K()).d;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsAudio, "setpageDiagramDetailsAudio");
                        return setpageDiagramDetailsAudio;
                    case 6:
                        int i62 = DiagramOverviewActivity.o1;
                        ImageView setpageDiagramDetailsClose = ((C4613q) diagramOverviewActivity.K()).e;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsClose, "setpageDiagramDetailsClose");
                        return setpageDiagramDetailsClose;
                    case 7:
                        int i72 = DiagramOverviewActivity.o1;
                        DiagramView setpageDiagramDetailsDiagramView = ((C4613q) diagramOverviewActivity.K()).f;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsDiagramView, "setpageDiagramDetailsDiagramView");
                        return setpageDiagramDetailsDiagramView;
                    case 8:
                        int i82 = DiagramOverviewActivity.o1;
                        QStarIconView setpageDiagramDetailsStar = ((C4613q) diagramOverviewActivity.K()).g;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsStar, "setpageDiagramDetailsStar");
                        return setpageDiagramDetailsStar;
                    case 9:
                        int i92 = DiagramOverviewActivity.o1;
                        QTextView setpageDiagramDetailsTermDefinition = ((C4613q) diagramOverviewActivity.K()).h;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsTermDefinition, "setpageDiagramDetailsTermDefinition");
                        return setpageDiagramDetailsTermDefinition;
                    case 10:
                        int i102 = DiagramOverviewActivity.o1;
                        QTextView setpageDiagramDetailsTermDefinitionLabel = ((C4613q) diagramOverviewActivity.K()).i;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsTermDefinitionLabel, "setpageDiagramDetailsTermDefinitionLabel");
                        return setpageDiagramDetailsTermDefinitionLabel;
                    case 11:
                        int i112 = DiagramOverviewActivity.o1;
                        QTextView setpageDiagramDetailsTermDiagramLabel = ((C4613q) diagramOverviewActivity.K()).j;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsTermDiagramLabel, "setpageDiagramDetailsTermDiagramLabel");
                        return setpageDiagramDetailsTermDiagramLabel;
                    case 12:
                        int i122 = DiagramOverviewActivity.o1;
                        ImageView setpageDiagramDetailsTermImage = ((C4613q) diagramOverviewActivity.K()).k;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsTermImage, "setpageDiagramDetailsTermImage");
                        return setpageDiagramDetailsTermImage;
                    case 13:
                        int i132 = DiagramOverviewActivity.o1;
                        View contentOverlay = ((C4613q) diagramOverviewActivity.K()).b;
                        Intrinsics.checkNotNullExpressionValue(contentOverlay, "contentOverlay");
                        return contentOverlay;
                    case 14:
                        int i142 = DiagramOverviewActivity.o1;
                        QTextView setpageDiagramDetailsTermWord = ((C4613q) diagramOverviewActivity.K()).l;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsTermWord, "setpageDiagramDetailsTermWord");
                        return setpageDiagramDetailsTermWord;
                    case 15:
                        com.quizlet.features.infra.legacyadapter.databinding.f fVar2 = diagramOverviewActivity.B;
                        if (fVar2 == null) {
                            Intrinsics.m("studyModeSettingsToolbarBinding");
                            throw null;
                        }
                        QTextView studyModeSettingsToolbarTitle = (QTextView) fVar2.d;
                        Intrinsics.checkNotNullExpressionValue(studyModeSettingsToolbarTitle, "studyModeSettingsToolbarTitle");
                        return studyModeSettingsToolbarTitle;
                    case 16:
                        com.quizlet.features.infra.legacyadapter.databinding.f fVar3 = diagramOverviewActivity.B;
                        if (fVar3 == null) {
                            Intrinsics.m("studyModeSettingsToolbarBinding");
                            throw null;
                        }
                        FrameLayout studyModeSettingsToolbarUpButton = (FrameLayout) fVar3.c;
                        Intrinsics.checkNotNullExpressionValue(studyModeSettingsToolbarUpButton, "studyModeSettingsToolbarUpButton");
                        return studyModeSettingsToolbarUpButton;
                    default:
                        com.quizlet.features.infra.legacyadapter.databinding.f fVar4 = diagramOverviewActivity.B;
                        if (fVar4 == null) {
                            Intrinsics.m("studyModeSettingsToolbarBinding");
                            throw null;
                        }
                        ImageView studyModeSettingsToolbarUpIcon = (ImageView) fVar4.e;
                        Intrinsics.checkNotNullExpressionValue(studyModeSettingsToolbarUpIcon, "studyModeSettingsToolbarUpIcon");
                        return studyModeSettingsToolbarUpIcon;
                }
            }
        });
        final int i18 = 3;
        this.f1 = l.b(new Function0(this) { // from class: com.quizlet.quizletandroid.ui.diagramming.a
            public final /* synthetic */ DiagramOverviewActivity b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                DiagramOverviewActivity diagramOverviewActivity = this.b;
                switch (i18) {
                    case 0:
                        int i22 = DiagramOverviewActivity.o1;
                        com.quizlet.infra.legacysyncengine.net.c cVar = diagramOverviewActivity.I;
                        if (cVar == null) {
                            Intrinsics.m("loader");
                            throw null;
                        }
                        long jLongValue = ((Number) diagramOverviewActivity.d1.getValue()).longValue();
                        UserInfoCache userInfoCache = diagramOverviewActivity.F;
                        if (userInfoCache != null) {
                            return new w(cVar, jLongValue, userInfoCache.getPersonId(), false, SortOption.ORIGINAL);
                        }
                        Intrinsics.m("userInfoCache");
                        throw null;
                    case 1:
                        int i32 = DiagramOverviewActivity.o1;
                        return Long.valueOf(diagramOverviewActivity.getIntent().getLongExtra("setId", 0L));
                    case 2:
                        return BottomSheetBehavior.C((NestedScrollView) diagramOverviewActivity.r.getValue());
                    case 3:
                        DiagramOverviewActivity diagramOverviewActivity2 = this.b;
                        com.quizlet.infra.legacysyncengine.managers.d dVar = diagramOverviewActivity2.J;
                        if (dVar == null) {
                            Intrinsics.m("loggedInUserManager");
                            throw null;
                        }
                        com.quizlet.infra.legacysyncengine.net.f fVar = diagramOverviewActivity2.H;
                        if (fVar == null) {
                            Intrinsics.m("syncDispatcher");
                            throw null;
                        }
                        com.quizlet.quizletandroid.managers.audio.h hVar = diagramOverviewActivity2.G;
                        if (hVar == null) {
                            Intrinsics.m("audioManager");
                            throw null;
                        }
                        io.ktor.client.plugins.api.d dVar2 = diagramOverviewActivity2.M;
                        if (dVar2 != null) {
                            return new com.quizlet.quizletandroid.ui.common.adapter.presenter.e(dVar, fVar, hVar, diagramOverviewActivity2, dVar2);
                        }
                        Intrinsics.m("audioPlayFailureManager");
                        throw null;
                    case 4:
                        int i42 = DiagramOverviewActivity.o1;
                        NestedScrollView setpageDiagramBottomSheet = ((C4613q) diagramOverviewActivity.K()).c;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramBottomSheet, "setpageDiagramBottomSheet");
                        return setpageDiagramBottomSheet;
                    case 5:
                        int i52 = DiagramOverviewActivity.o1;
                        StatefulIconFontTextView setpageDiagramDetailsAudio = ((C4613q) diagramOverviewActivity.K()).d;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsAudio, "setpageDiagramDetailsAudio");
                        return setpageDiagramDetailsAudio;
                    case 6:
                        int i62 = DiagramOverviewActivity.o1;
                        ImageView setpageDiagramDetailsClose = ((C4613q) diagramOverviewActivity.K()).e;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsClose, "setpageDiagramDetailsClose");
                        return setpageDiagramDetailsClose;
                    case 7:
                        int i72 = DiagramOverviewActivity.o1;
                        DiagramView setpageDiagramDetailsDiagramView = ((C4613q) diagramOverviewActivity.K()).f;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsDiagramView, "setpageDiagramDetailsDiagramView");
                        return setpageDiagramDetailsDiagramView;
                    case 8:
                        int i82 = DiagramOverviewActivity.o1;
                        QStarIconView setpageDiagramDetailsStar = ((C4613q) diagramOverviewActivity.K()).g;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsStar, "setpageDiagramDetailsStar");
                        return setpageDiagramDetailsStar;
                    case 9:
                        int i92 = DiagramOverviewActivity.o1;
                        QTextView setpageDiagramDetailsTermDefinition = ((C4613q) diagramOverviewActivity.K()).h;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsTermDefinition, "setpageDiagramDetailsTermDefinition");
                        return setpageDiagramDetailsTermDefinition;
                    case 10:
                        int i102 = DiagramOverviewActivity.o1;
                        QTextView setpageDiagramDetailsTermDefinitionLabel = ((C4613q) diagramOverviewActivity.K()).i;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsTermDefinitionLabel, "setpageDiagramDetailsTermDefinitionLabel");
                        return setpageDiagramDetailsTermDefinitionLabel;
                    case 11:
                        int i112 = DiagramOverviewActivity.o1;
                        QTextView setpageDiagramDetailsTermDiagramLabel = ((C4613q) diagramOverviewActivity.K()).j;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsTermDiagramLabel, "setpageDiagramDetailsTermDiagramLabel");
                        return setpageDiagramDetailsTermDiagramLabel;
                    case 12:
                        int i122 = DiagramOverviewActivity.o1;
                        ImageView setpageDiagramDetailsTermImage = ((C4613q) diagramOverviewActivity.K()).k;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsTermImage, "setpageDiagramDetailsTermImage");
                        return setpageDiagramDetailsTermImage;
                    case 13:
                        int i132 = DiagramOverviewActivity.o1;
                        View contentOverlay = ((C4613q) diagramOverviewActivity.K()).b;
                        Intrinsics.checkNotNullExpressionValue(contentOverlay, "contentOverlay");
                        return contentOverlay;
                    case 14:
                        int i142 = DiagramOverviewActivity.o1;
                        QTextView setpageDiagramDetailsTermWord = ((C4613q) diagramOverviewActivity.K()).l;
                        Intrinsics.checkNotNullExpressionValue(setpageDiagramDetailsTermWord, "setpageDiagramDetailsTermWord");
                        return setpageDiagramDetailsTermWord;
                    case 15:
                        com.quizlet.features.infra.legacyadapter.databinding.f fVar2 = diagramOverviewActivity.B;
                        if (fVar2 == null) {
                            Intrinsics.m("studyModeSettingsToolbarBinding");
                            throw null;
                        }
                        QTextView studyModeSettingsToolbarTitle = (QTextView) fVar2.d;
                        Intrinsics.checkNotNullExpressionValue(studyModeSettingsToolbarTitle, "studyModeSettingsToolbarTitle");
                        return studyModeSettingsToolbarTitle;
                    case 16:
                        com.quizlet.features.infra.legacyadapter.databinding.f fVar3 = diagramOverviewActivity.B;
                        if (fVar3 == null) {
                            Intrinsics.m("studyModeSettingsToolbarBinding");
                            throw null;
                        }
                        FrameLayout studyModeSettingsToolbarUpButton = (FrameLayout) fVar3.c;
                        Intrinsics.checkNotNullExpressionValue(studyModeSettingsToolbarUpButton, "studyModeSettingsToolbarUpButton");
                        return studyModeSettingsToolbarUpButton;
                    default:
                        com.quizlet.features.infra.legacyadapter.databinding.f fVar4 = diagramOverviewActivity.B;
                        if (fVar4 == null) {
                            Intrinsics.m("studyModeSettingsToolbarBinding");
                            throw null;
                        }
                        ImageView studyModeSettingsToolbarUpIcon = (ImageView) fVar4.e;
                        Intrinsics.checkNotNullExpressionValue(studyModeSettingsToolbarUpIcon, "studyModeSettingsToolbarUpIcon");
                        return studyModeSettingsToolbarUpIcon;
                }
            }
        });
        this.h1 = V.c();
        this.i1 = new io.reactivex.rxjava3.disposables.a();
        final int i19 = 0;
        this.j1 = new io.reactivex.rxjava3.functions.d(this) { // from class: com.quizlet.quizletandroid.ui.diagramming.b
            public final /* synthetic */ DiagramOverviewActivity b;

            {
                this.b = this;
            }

            /* JADX WARN: Type inference failed for: r6v15, types: [java.lang.Object, java.util.Map] */
            @Override // io.reactivex.rxjava3.functions.d
            public final void accept(Object obj) throws IOException {
                DiagramOverviewActivity diagramOverviewActivity = this.b;
                switch (i19) {
                    case 0:
                        DiagramData it2 = (DiagramData) obj;
                        int i20 = DiagramOverviewActivity.o1;
                        Intrinsics.checkNotNullParameter(it2, "it");
                        u uVar = diagramOverviewActivity.u;
                        ((DiagramView) uVar.getValue()).d(it2, new com.quizlet.diagrams.b[0]);
                        ((QTextView) diagramOverviewActivity.y.getValue()).setVisibility(0);
                        ((DiagramView) uVar.getValue()).setVisibility(0);
                        break;
                    case 1:
                        int i21 = DiagramOverviewActivity.o1;
                        Intrinsics.checkNotNullParameter((Throwable) obj, "it");
                        ((QTextView) diagramOverviewActivity.y.getValue()).setVisibility(8);
                        ((DiagramView) diagramOverviewActivity.u.getValue()).setVisibility(8);
                        break;
                    default:
                        int i22 = DiagramOverviewActivity.o1;
                        Intrinsics.checkNotNullParameter((List) obj, "it");
                        Pair pair = (Pair) diagramOverviewActivity.h1.get(Long.valueOf(diagramOverviewActivity.g1));
                        if (pair != null) {
                            diagramOverviewActivity.b0(pair);
                            break;
                        }
                        break;
                }
            }
        };
        final int i20 = 1;
        this.k1 = new io.reactivex.rxjava3.functions.d(this) { // from class: com.quizlet.quizletandroid.ui.diagramming.b
            public final /* synthetic */ DiagramOverviewActivity b;

            {
                this.b = this;
            }

            /* JADX WARN: Type inference failed for: r6v15, types: [java.lang.Object, java.util.Map] */
            @Override // io.reactivex.rxjava3.functions.d
            public final void accept(Object obj) throws IOException {
                DiagramOverviewActivity diagramOverviewActivity = this.b;
                switch (i20) {
                    case 0:
                        DiagramData it2 = (DiagramData) obj;
                        int i202 = DiagramOverviewActivity.o1;
                        Intrinsics.checkNotNullParameter(it2, "it");
                        u uVar = diagramOverviewActivity.u;
                        ((DiagramView) uVar.getValue()).d(it2, new com.quizlet.diagrams.b[0]);
                        ((QTextView) diagramOverviewActivity.y.getValue()).setVisibility(0);
                        ((DiagramView) uVar.getValue()).setVisibility(0);
                        break;
                    case 1:
                        int i21 = DiagramOverviewActivity.o1;
                        Intrinsics.checkNotNullParameter((Throwable) obj, "it");
                        ((QTextView) diagramOverviewActivity.y.getValue()).setVisibility(8);
                        ((DiagramView) diagramOverviewActivity.u.getValue()).setVisibility(8);
                        break;
                    default:
                        int i22 = DiagramOverviewActivity.o1;
                        Intrinsics.checkNotNullParameter((List) obj, "it");
                        Pair pair = (Pair) diagramOverviewActivity.h1.get(Long.valueOf(diagramOverviewActivity.g1));
                        if (pair != null) {
                            diagramOverviewActivity.b0(pair);
                            break;
                        }
                        break;
                }
            }
        };
        final int i21 = 2;
        this.l1 = new io.reactivex.rxjava3.functions.d(this) { // from class: com.quizlet.quizletandroid.ui.diagramming.b
            public final /* synthetic */ DiagramOverviewActivity b;

            {
                this.b = this;
            }

            /* JADX WARN: Type inference failed for: r6v15, types: [java.lang.Object, java.util.Map] */
            @Override // io.reactivex.rxjava3.functions.d
            public final void accept(Object obj) throws IOException {
                DiagramOverviewActivity diagramOverviewActivity = this.b;
                switch (i21) {
                    case 0:
                        DiagramData it2 = (DiagramData) obj;
                        int i202 = DiagramOverviewActivity.o1;
                        Intrinsics.checkNotNullParameter(it2, "it");
                        u uVar = diagramOverviewActivity.u;
                        ((DiagramView) uVar.getValue()).d(it2, new com.quizlet.diagrams.b[0]);
                        ((QTextView) diagramOverviewActivity.y.getValue()).setVisibility(0);
                        ((DiagramView) uVar.getValue()).setVisibility(0);
                        break;
                    case 1:
                        int i212 = DiagramOverviewActivity.o1;
                        Intrinsics.checkNotNullParameter((Throwable) obj, "it");
                        ((QTextView) diagramOverviewActivity.y.getValue()).setVisibility(8);
                        ((DiagramView) diagramOverviewActivity.u.getValue()).setVisibility(8);
                        break;
                    default:
                        int i22 = DiagramOverviewActivity.o1;
                        Intrinsics.checkNotNullParameter((List) obj, "it");
                        Pair pair = (Pair) diagramOverviewActivity.h1.get(Long.valueOf(diagramOverviewActivity.g1));
                        if (pair != null) {
                            diagramOverviewActivity.b0(pair);
                            break;
                        }
                        break;
                }
            }
        };
        this.m1 = new com.quizlet.infra.legacysyncengine.models.serializers.a(17);
        this.n1 = new com.google.android.material.bottomsheet.f(this, 2);
    }

    @Override // com.quizlet.baseui.base.b
    public final String D() {
        return "DiagramOverviewActvity";
    }

    @Override // com.quizlet.baseui.base.b
    public final void F() {
        super.F();
        com.quizlet.data.repository.login.a aVar = this.Z;
        if (aVar == null) {
            Intrinsics.m("diagramOverviewDataProvider");
            throw null;
        }
        ((com.quizlet.features.infra.studysetting.datasource.a) aVar.a).d();
        ((com.quizlet.features.infra.studysetting.datasource.a) aVar.b).d();
        ((com.quizlet.features.infra.studysetting.datasource.a) aVar.c).d();
    }

    @Override // com.quizlet.baseui.base.f
    public final androidx.viewbinding.a N() {
        View viewInflate = getLayoutInflater().inflate(R.layout.diagram_overview_activity, (ViewGroup) null, false);
        int i = R.id.content_overlay;
        View viewC = AbstractC3375o2.c(R.id.content_overlay, viewInflate);
        if (viewC != null) {
            i = R.id.end_guideline;
            if (((Guideline) AbstractC3375o2.c(R.id.end_guideline, viewInflate)) != null) {
                i = R.id.setpage_diagram_bottom_sheet;
                NestedScrollView nestedScrollView = (NestedScrollView) AbstractC3375o2.c(R.id.setpage_diagram_bottom_sheet, viewInflate);
                if (nestedScrollView != null) {
                    i = R.id.setpage_diagram_content;
                    if (((LinearLayout) AbstractC3375o2.c(R.id.setpage_diagram_content, viewInflate)) != null) {
                        CoordinatorLayout coordinatorLayout = (CoordinatorLayout) viewInflate;
                        i = R.id.setpage_diagram_details_audio;
                        StatefulIconFontTextView statefulIconFontTextView = (StatefulIconFontTextView) AbstractC3375o2.c(R.id.setpage_diagram_details_audio, viewInflate);
                        if (statefulIconFontTextView != null) {
                            i = R.id.setpage_diagram_details_close;
                            ImageView imageView = (ImageView) AbstractC3375o2.c(R.id.setpage_diagram_details_close, viewInflate);
                            if (imageView != null) {
                                i = R.id.setpage_diagram_details_diagram_view;
                                DiagramView diagramView = (DiagramView) AbstractC3375o2.c(R.id.setpage_diagram_details_diagram_view, viewInflate);
                                if (diagramView != null) {
                                    i = R.id.setpage_diagram_details_star;
                                    QStarIconView qStarIconView = (QStarIconView) AbstractC3375o2.c(R.id.setpage_diagram_details_star, viewInflate);
                                    if (qStarIconView != null) {
                                        i = R.id.setpage_diagram_details_term_definition;
                                        QTextView qTextView = (QTextView) AbstractC3375o2.c(R.id.setpage_diagram_details_term_definition, viewInflate);
                                        if (qTextView != null) {
                                            i = R.id.setpage_diagram_details_term_definition_label;
                                            QTextView qTextView2 = (QTextView) AbstractC3375o2.c(R.id.setpage_diagram_details_term_definition_label, viewInflate);
                                            if (qTextView2 != null) {
                                                i = R.id.setpage_diagram_details_term_diagram_label;
                                                QTextView qTextView3 = (QTextView) AbstractC3375o2.c(R.id.setpage_diagram_details_term_diagram_label, viewInflate);
                                                if (qTextView3 != null) {
                                                    i = R.id.setpage_diagram_details_term_image;
                                                    ImageView imageView2 = (ImageView) AbstractC3375o2.c(R.id.setpage_diagram_details_term_image, viewInflate);
                                                    if (imageView2 != null) {
                                                        i = R.id.setpage_diagram_details_term_label;
                                                        if (((QTextView) AbstractC3375o2.c(R.id.setpage_diagram_details_term_label, viewInflate)) != null) {
                                                            i = R.id.setpage_diagram_details_term_word;
                                                            QTextView qTextView4 = (QTextView) AbstractC3375o2.c(R.id.setpage_diagram_details_term_word, viewInflate);
                                                            if (qTextView4 != null) {
                                                                i = R.id.setpage_diagram_overview_fragment;
                                                                FrameLayout frameLayout = (FrameLayout) AbstractC3375o2.c(R.id.setpage_diagram_overview_fragment, viewInflate);
                                                                if (frameLayout != null) {
                                                                    i = R.id.start_guideline;
                                                                    if (((Guideline) AbstractC3375o2.c(R.id.start_guideline, viewInflate)) != null) {
                                                                        i = R.id.studymode_settings_toolbar;
                                                                        View viewC2 = AbstractC3375o2.c(R.id.studymode_settings_toolbar, viewInflate);
                                                                        if (viewC2 != null) {
                                                                            C4613q c4613q = new C4613q(coordinatorLayout, viewC, nestedScrollView, statefulIconFontTextView, imageView, diagramView, qStarIconView, qTextView, qTextView2, qTextView3, imageView2, qTextView4, frameLayout, com.quizlet.features.infra.legacyadapter.databinding.f.b(viewC2));
                                                                            Intrinsics.checkNotNullExpressionValue(c4613q, "inflate(...)");
                                                                            return c4613q;
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(viewInflate.getResources().getResourceName(i)));
    }

    public final void b0(final Pair pair) {
        DBTerm dBTerm = (DBTerm) pair.a;
        DBSelectedTerm dBSelectedTerm = (DBSelectedTerm) pair.b;
        ((QTextView) this.A.getValue()).setText(dBTerm.getText(O1.WORD));
        O1 o12 = O1.DEFINITION;
        String text = dBTerm.getText(o12);
        if (text == null) {
            text = "";
        }
        boolean zO = StringsKt.O(text);
        u uVar = this.x;
        u uVar2 = this.w;
        if (zO) {
            ((QTextView) uVar.getValue()).setVisibility(8);
            ((QTextView) uVar2.getValue()).setVisibility(8);
        } else {
            ((QTextView) uVar2.getValue()).setText(dBTerm.getText(o12));
            ((QTextView) uVar.getValue()).setVisibility(0);
            ((QTextView) uVar2.getValue()).setVisibility(0);
        }
        boolean zHasDefinitionImage = dBTerm.hasDefinitionImage();
        u uVar3 = this.z;
        if (!zHasDefinitionImage) {
            ((ImageView) uVar3.getValue()).setVisibility(8);
        } else {
            if (this.L == null) {
                Intrinsics.m("imageLoader");
                throw null;
            }
            m mRequestManager = Glide.c(this);
            Intrinsics.checkNotNullParameter(mRequestManager, "mRequestManager");
            String url = dBTerm.getDefinitionImageUrl();
            Intrinsics.e(url, "null cannot be cast to non-null type kotlin.String");
            Intrinsics.checkNotNullParameter(url, "url");
            com.quizlet.qutils.data.offline.c ttl = com.quizlet.qutils.data.offline.c.b;
            Intrinsics.checkNotNullParameter(url, "url");
            Intrinsics.checkNotNullParameter(ttl, "ttl");
            com.quizlet.quizletandroid.ui.common.images.loading.offline.a aVar = new com.quizlet.quizletandroid.ui.common.images.loading.offline.a(url);
            mRequestManager.getClass();
            com.bumptech.glide.k kVarD = new com.bumptech.glide.k(mRequestManager.a, mRequestManager, Drawable.class, mRequestManager.b).D(aVar);
            com.bumptech.glide.request.f fVar = new com.bumptech.glide.request.f();
            ImageView imageView = (ImageView) uVar3.getValue();
            kVarD.b(fVar);
            try {
                kVarD.z(imageView);
            } catch (IllegalArgumentException e) {
                timber.log.c.a(e);
                imageView.setImageDrawable(null);
            }
            ((QTextView) uVar.getValue()).setVisibility(0);
            ((ImageView) uVar3.getValue()).setVisibility(0);
        }
        p pVarO = p.o(this.X, this.W, this.V, new com.quizlet.infra.legacysyncengine.tasks.parse.b(dBTerm, 3));
        Intrinsics.checkNotNullExpressionValue(pVarO, "zip(...)");
        pVarO.i(this.j1, this.k1);
        final int i = 0;
        ((StatefulIconFontTextView) this.s.getValue()).setOnClickListener(new View.OnClickListener(this) { // from class: com.quizlet.quizletandroid.ui.diagramming.d
            public final /* synthetic */ DiagramOverviewActivity b;

            {
                this.b = this;
            }

            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                Pair termData = pair;
                switch (i) {
                    case 0:
                        int i2 = DiagramOverviewActivity.o1;
                        DiagramOverviewActivity diagramOverviewActivity = this.b;
                        diagramOverviewActivity.getClass();
                        Intrinsics.checkNotNullParameter(termData, "termData");
                        ((com.quizlet.quizletandroid.ui.common.adapter.presenter.e) diagramOverviewActivity.f1.getValue()).c(diagramOverviewActivity, diagramOverviewActivity.m1, (DBTerm) termData.a, O1.WORD, true);
                        break;
                    default:
                        int i3 = DiagramOverviewActivity.o1;
                        DiagramOverviewActivity diagramOverviewActivity2 = this.b;
                        diagramOverviewActivity2.getClass();
                        Intrinsics.checkNotNullParameter(termData, "termData");
                        ((com.quizlet.quizletandroid.ui.common.adapter.presenter.e) diagramOverviewActivity2.f1.getValue()).b((DBTerm) termData.a, (DBSelectedTerm) termData.b, 0);
                        break;
                }
            }
        });
        u uVar4 = this.v;
        ((QStarIconView) uVar4.getValue()).setSelected(dBSelectedTerm != null);
        final int i2 = 1;
        ((QStarIconView) uVar4.getValue()).setOnClickListener(new View.OnClickListener(this) { // from class: com.quizlet.quizletandroid.ui.diagramming.d
            public final /* synthetic */ DiagramOverviewActivity b;

            {
                this.b = this;
            }

            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                Pair termData = pair;
                switch (i2) {
                    case 0:
                        int i22 = DiagramOverviewActivity.o1;
                        DiagramOverviewActivity diagramOverviewActivity = this.b;
                        diagramOverviewActivity.getClass();
                        Intrinsics.checkNotNullParameter(termData, "termData");
                        ((com.quizlet.quizletandroid.ui.common.adapter.presenter.e) diagramOverviewActivity.f1.getValue()).c(diagramOverviewActivity, diagramOverviewActivity.m1, (DBTerm) termData.a, O1.WORD, true);
                        break;
                    default:
                        int i3 = DiagramOverviewActivity.o1;
                        DiagramOverviewActivity diagramOverviewActivity2 = this.b;
                        diagramOverviewActivity2.getClass();
                        Intrinsics.checkNotNullParameter(termData, "termData");
                        ((com.quizlet.quizletandroid.ui.common.adapter.presenter.e) diagramOverviewActivity2.f1.getValue()).b((DBTerm) termData.a, (DBSelectedTerm) termData.b, 0);
                        break;
                }
            }
        });
        this.g1 = dBTerm.getId();
    }

    public final BottomSheetBehavior c0() {
        return (BottomSheetBehavior) this.e1.getValue();
    }

    public final View d0() {
        return (View) this.q.getValue();
    }

    @Override // com.quizlet.quizletandroid.ui.common.adapter.e
    public final void e(String str) {
    }

    @Override // com.quizlet.infra.legacysyncengine.datasources.b
    public final void h(List data) {
        Intrinsics.checkNotNullParameter(data, "data");
        this.Y.b(data);
        ArrayList arrayList = new ArrayList(C.q(data, 10));
        Iterator it2 = data.iterator();
        while (it2.hasNext()) {
            Pair pair = (Pair) it2.next();
            arrayList.add(new Pair(Long.valueOf(((DBTerm) pair.a).getId()), pair));
        }
        Pair[] pairArr = (Pair[]) arrayList.toArray(new Pair[0]);
        this.h1 = V.e((Pair[]) Arrays.copyOf(pairArr, pairArr.length));
    }

    @Override // androidx.activity.s, android.app.Activity
    public final void onBackPressed() {
        if (c0().L == 3) {
            c0().J(5);
        } else {
            super.onBackPressed();
        }
    }

    @Override // com.quizlet.ads.ui.activity.d, com.quizlet.baseui.base.f, com.quizlet.baseui.base.b, androidx.fragment.app.I, androidx.activity.s, androidx.core.app.AbstractActivityC1021h, android.app.Activity
    public final void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        v.b(this, null, 3);
        CoordinatorLayout coordinatorLayout = ((C4613q) K()).a;
        Intrinsics.checkNotNullExpressionValue(coordinatorLayout, "getRoot(...)");
        AbstractC3188k6.a(coordinatorLayout);
        this.B = ((C4613q) K()).n;
        com.quizlet.infra.legacysyncengine.net.c loader = this.I;
        if (loader == null) {
            Intrinsics.m("loader");
            throw null;
        }
        u uVar = this.d1;
        long jLongValue = ((Number) uVar.getValue()).longValue();
        Intrinsics.checkNotNullParameter(loader, "loader");
        com.quizlet.data.repository.login.a aVar = new com.quizlet.data.repository.login.a();
        Intrinsics.checkNotNullParameter(loader, "loader");
        com.quizlet.infra.legacysyncengine.orm.b bVar = new com.quizlet.infra.legacysyncengine.orm.b(Models.STUDY_SET);
        bVar.b(Long.valueOf(jLongValue), DBStudySetFields.ID);
        bVar.e(DBStudySetFields.CREATOR);
        aVar.a = new com.quizlet.features.infra.studysetting.datasource.a(loader, bVar.a());
        aVar.b = new com.quizlet.features.infra.studysetting.datasource.a(loader, jLongValue, 7);
        aVar.c = new com.quizlet.features.infra.studysetting.datasource.a(loader, jLongValue, 5);
        this.Z = aVar;
        getSupportFragmentManager().b(new com.quizlet.explanations.textbook.ui.b(this, 2));
        if (getSupportFragmentManager().E("DiagramOverviewFragment") == null) {
            long jLongValue2 = ((Number) uVar.getValue()).longValue();
            DiagramOverviewFragment diagramOverviewFragment = new DiagramOverviewFragment();
            Bundle bundle2 = new Bundle();
            bundle2.putLong("setId", jLongValue2);
            diagramOverviewFragment.setArguments(bundle2);
            AbstractC1136h0 supportFragmentManager = getSupportFragmentManager();
            supportFragmentManager.getClass();
            C1121a c1121a = new C1121a(supportFragmentManager);
            c1121a.i(R.id.setpage_diagram_overview_fragment, diagramOverviewFragment, "DiagramOverviewFragment", 1);
            c1121a.g();
        }
    }

    @Override // com.quizlet.ads.ui.activity.d, com.quizlet.baseui.base.b, androidx.appcompat.app.AbstractActivityC0055k, androidx.fragment.app.I, android.app.Activity
    public final void onDestroy() {
        ((w) this.c1.getValue()).a(this);
        super.onDestroy();
    }

    @Override // com.quizlet.baseui.base.b, androidx.appcompat.app.AbstractActivityC0055k, android.app.Activity
    public final void onPostCreate(Bundle bundle) throws Resources.NotFoundException {
        super.onPostCreate(bundle);
        ((QTextView) this.C.getValue()).setText(R.string.diagram_overview_title);
        ((ImageView) this.E.getValue()).setImageResource(R.drawable.ic_sys_close_x);
        final int i = 0;
        ((FrameLayout) this.D.getValue()).setOnClickListener(new View.OnClickListener(this) { // from class: com.quizlet.quizletandroid.ui.diagramming.c
            public final /* synthetic */ DiagramOverviewActivity b;

            {
                this.b = this;
            }

            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                DiagramOverviewActivity diagramOverviewActivity = this.b;
                switch (i) {
                    case 0:
                        int i2 = DiagramOverviewActivity.o1;
                        diagramOverviewActivity.finish();
                        break;
                    case 1:
                        int i3 = DiagramOverviewActivity.o1;
                        diagramOverviewActivity.c0().J(5);
                        break;
                    default:
                        int i4 = DiagramOverviewActivity.o1;
                        diagramOverviewActivity.c0().J(5);
                        break;
                }
            }
        });
        final int i2 = 1;
        ((ImageView) this.t.getValue()).setOnClickListener(new View.OnClickListener(this) { // from class: com.quizlet.quizletandroid.ui.diagramming.c
            public final /* synthetic */ DiagramOverviewActivity b;

            {
                this.b = this;
            }

            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                DiagramOverviewActivity diagramOverviewActivity = this.b;
                switch (i2) {
                    case 0:
                        int i22 = DiagramOverviewActivity.o1;
                        diagramOverviewActivity.finish();
                        break;
                    case 1:
                        int i3 = DiagramOverviewActivity.o1;
                        diagramOverviewActivity.c0().J(5);
                        break;
                    default:
                        int i4 = DiagramOverviewActivity.o1;
                        diagramOverviewActivity.c0().J(5);
                        break;
                }
            }
        });
        ((DiagramView) this.u.getValue()).f();
        final int i3 = 2;
        d0().setOnClickListener(new View.OnClickListener(this) { // from class: com.quizlet.quizletandroid.ui.diagramming.c
            public final /* synthetic */ DiagramOverviewActivity b;

            {
                this.b = this;
            }

            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                DiagramOverviewActivity diagramOverviewActivity = this.b;
                switch (i3) {
                    case 0:
                        int i22 = DiagramOverviewActivity.o1;
                        diagramOverviewActivity.finish();
                        break;
                    case 1:
                        int i32 = DiagramOverviewActivity.o1;
                        diagramOverviewActivity.c0().J(5);
                        break;
                    default:
                        int i4 = DiagramOverviewActivity.o1;
                        diagramOverviewActivity.c0().J(5);
                        break;
                }
            }
        });
        d0().setClickable(false);
        c0().H(true);
        c0().J = true;
        c0().J(5);
        BottomSheetBehavior bottomSheetBehaviorC0 = c0();
        bottomSheetBehaviorC0.getClass();
        Log.w("BottomSheetBehavior", "BottomSheetBehavior now supports multiple callbacks. `setBottomSheetCallback()` removes all existing callbacks, including ones set internally by library authors, which may result in unintended behavior. This may change in the future. Please use `addBottomSheetCallback()` and `removeBottomSheetCallback()` instead to set your own callbacks.");
        ArrayList arrayList = bottomSheetBehaviorC0.g1;
        arrayList.clear();
        com.google.android.material.bottomsheet.f fVar = this.n1;
        if (fVar != null) {
            arrayList.add(fVar);
        }
        u uVar = this.c1;
        ((w) uVar.getValue()).e(this);
        ((w) uVar.getValue()).d();
    }

    @Override // com.quizlet.baseui.base.b, androidx.appcompat.app.AbstractActivityC0055k, androidx.fragment.app.I, android.app.Activity
    public final void onStart() {
        super.onStart();
        o oVar = this.K;
        if (oVar == null) {
            Intrinsics.m("mainThreadScheduler");
            throw null;
        }
        W wS = this.Y.s(oVar);
        com.quizlet.infra.legacysyncengine.net.request.g gVar = io.reactivex.rxjava3.internal.functions.d.d;
        io.reactivex.rxjava3.internal.functions.b bVar = io.reactivex.rxjava3.internal.functions.d.c;
        io.reactivex.rxjava3.disposables.b bVarU = wS.u(this.l1, gVar, bVar);
        Intrinsics.checkNotNullExpressionValue(bVarU, "subscribe(...)");
        A7.a(bVarU, this.i1);
        com.quizlet.data.repository.login.a aVar = this.Z;
        if (aVar == null) {
            Intrinsics.m("diagramOverviewDataProvider");
            throw null;
        }
        J jQ = ((com.quizlet.features.infra.studysetting.datasource.a) aVar.a).f().l(com.quizlet.quizletandroid.ui.diagramming.data.a.d).q(com.quizlet.quizletandroid.ui.diagramming.data.a.e);
        Intrinsics.checkNotNullExpressionValue(jQ, "map(...)");
        final int i = 0;
        io.reactivex.rxjava3.internal.operators.observable.C c = new io.reactivex.rxjava3.internal.operators.observable.C(jQ.s(io.reactivex.rxjava3.android.schedulers.b.a()), new io.reactivex.rxjava3.functions.d(this) { // from class: com.quizlet.quizletandroid.ui.diagramming.e
            public final /* synthetic */ DiagramOverviewActivity b;

            {
                this.b = this;
            }

            @Override // io.reactivex.rxjava3.functions.d
            public final void accept(Object obj) {
                DiagramOverviewActivity diagramOverviewActivity = this.b;
                switch (i) {
                    case 0:
                        io.reactivex.rxjava3.disposables.b p0 = (io.reactivex.rxjava3.disposables.b) obj;
                        Intrinsics.checkNotNullParameter(p0, "p0");
                        int i2 = DiagramOverviewActivity.o1;
                        diagramOverviewActivity.x(p0);
                        break;
                    case 1:
                        io.reactivex.rxjava3.disposables.b p02 = (io.reactivex.rxjava3.disposables.b) obj;
                        Intrinsics.checkNotNullParameter(p02, "p0");
                        int i3 = DiagramOverviewActivity.o1;
                        diagramOverviewActivity.x(p02);
                        break;
                    default:
                        io.reactivex.rxjava3.disposables.b p03 = (io.reactivex.rxjava3.disposables.b) obj;
                        Intrinsics.checkNotNullParameter(p03, "p0");
                        int i4 = DiagramOverviewActivity.o1;
                        diagramOverviewActivity.x(p03);
                        break;
                }
            }
        }, bVar);
        com.quizlet.features.match.game.b bVar2 = new com.quizlet.features.match.game.b(this.V, 1);
        com.quizlet.infra.legacysyncengine.net.request.g gVar2 = io.reactivex.rxjava3.internal.functions.d.e;
        c.u(bVar2, gVar2, bVar);
        com.quizlet.data.repository.login.a aVar2 = this.Z;
        if (aVar2 == null) {
            Intrinsics.m("diagramOverviewDataProvider");
            throw null;
        }
        J jQ2 = ((com.quizlet.features.infra.studysetting.datasource.a) aVar2.b).f().l(com.quizlet.quizletandroid.ui.diagramming.data.a.b).q(com.quizlet.quizletandroid.ui.diagramming.data.a.c);
        Intrinsics.checkNotNullExpressionValue(jQ2, "map(...)");
        final int i2 = 1;
        new io.reactivex.rxjava3.internal.operators.observable.C(jQ2.s(io.reactivex.rxjava3.android.schedulers.b.a()), new io.reactivex.rxjava3.functions.d(this) { // from class: com.quizlet.quizletandroid.ui.diagramming.e
            public final /* synthetic */ DiagramOverviewActivity b;

            {
                this.b = this;
            }

            @Override // io.reactivex.rxjava3.functions.d
            public final void accept(Object obj) {
                DiagramOverviewActivity diagramOverviewActivity = this.b;
                switch (i2) {
                    case 0:
                        io.reactivex.rxjava3.disposables.b p0 = (io.reactivex.rxjava3.disposables.b) obj;
                        Intrinsics.checkNotNullParameter(p0, "p0");
                        int i22 = DiagramOverviewActivity.o1;
                        diagramOverviewActivity.x(p0);
                        break;
                    case 1:
                        io.reactivex.rxjava3.disposables.b p02 = (io.reactivex.rxjava3.disposables.b) obj;
                        Intrinsics.checkNotNullParameter(p02, "p0");
                        int i3 = DiagramOverviewActivity.o1;
                        diagramOverviewActivity.x(p02);
                        break;
                    default:
                        io.reactivex.rxjava3.disposables.b p03 = (io.reactivex.rxjava3.disposables.b) obj;
                        Intrinsics.checkNotNullParameter(p03, "p0");
                        int i4 = DiagramOverviewActivity.o1;
                        diagramOverviewActivity.x(p03);
                        break;
                }
            }
        }, bVar).u(new com.quizlet.features.match.game.b(this.X, 2), gVar2, bVar);
        com.quizlet.data.repository.login.a aVar3 = this.Z;
        if (aVar3 == null) {
            Intrinsics.m("diagramOverviewDataProvider");
            throw null;
        }
        io.reactivex.rxjava3.core.i iVarF = ((com.quizlet.features.infra.studysetting.datasource.a) aVar3.c).f();
        Intrinsics.checkNotNullExpressionValue(iVarF, "getObservable(...)");
        final int i3 = 2;
        new io.reactivex.rxjava3.internal.operators.observable.C(iVarF.s(io.reactivex.rxjava3.android.schedulers.b.a()), new io.reactivex.rxjava3.functions.d(this) { // from class: com.quizlet.quizletandroid.ui.diagramming.e
            public final /* synthetic */ DiagramOverviewActivity b;

            {
                this.b = this;
            }

            @Override // io.reactivex.rxjava3.functions.d
            public final void accept(Object obj) {
                DiagramOverviewActivity diagramOverviewActivity = this.b;
                switch (i3) {
                    case 0:
                        io.reactivex.rxjava3.disposables.b p0 = (io.reactivex.rxjava3.disposables.b) obj;
                        Intrinsics.checkNotNullParameter(p0, "p0");
                        int i22 = DiagramOverviewActivity.o1;
                        diagramOverviewActivity.x(p0);
                        break;
                    case 1:
                        io.reactivex.rxjava3.disposables.b p02 = (io.reactivex.rxjava3.disposables.b) obj;
                        Intrinsics.checkNotNullParameter(p02, "p0");
                        int i32 = DiagramOverviewActivity.o1;
                        diagramOverviewActivity.x(p02);
                        break;
                    default:
                        io.reactivex.rxjava3.disposables.b p03 = (io.reactivex.rxjava3.disposables.b) obj;
                        Intrinsics.checkNotNullParameter(p03, "p0");
                        int i4 = DiagramOverviewActivity.o1;
                        diagramOverviewActivity.x(p03);
                        break;
                }
            }
        }, bVar).u(new com.quizlet.features.match.game.b(this.W, 3), gVar2, bVar);
    }

    @Override // com.quizlet.baseui.base.b, androidx.appcompat.app.AbstractActivityC0055k, androidx.fragment.app.I, android.app.Activity
    public final void onStop() {
        com.quizlet.data.repository.login.a aVar = this.Z;
        if (aVar == null) {
            Intrinsics.m("diagramOverviewDataProvider");
            throw null;
        }
        ((com.quizlet.features.infra.studysetting.datasource.a) aVar.a).g();
        ((com.quizlet.features.infra.studysetting.datasource.a) aVar.b).g();
        ((com.quizlet.features.infra.studysetting.datasource.a) aVar.c).g();
        this.i1.d();
        super.onStop();
    }
}
