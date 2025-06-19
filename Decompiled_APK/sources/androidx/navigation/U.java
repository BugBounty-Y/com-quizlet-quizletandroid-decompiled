package androidx.navigation;

import android.os.Handler;
import android.os.Looper;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewParent;
import android.widget.FrameLayout;
import androidx.appcompat.widget.AppCompatImageView;
import androidx.compose.animation.C0293u;
import com.braze.BrazeUser;
import com.braze.enums.Gender;
import com.braze.managers.BrazeGeofenceManager;
import com.braze.managers.C1498k;
import com.braze.storage.h0;
import com.braze.ui.UserJavascriptInterfaceBase;
import com.braze.ui.actions.brazeactions.steps.RemoveFromCustomAttributeArrayStep;
import com.braze.ui.actions.brazeactions.steps.StepData;
import com.comscore.streaming.EventType;
import com.facebook.internal.C1553h;
import com.google.android.gms.ads.admanager.AdManagerAdView;
import com.google.android.gms.ads.internal.client.F0;
import com.google.android.gms.ads.nativead.NativeCustomFormatAd;
import com.google.android.gms.internal.ads.C2568rb;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3188k6;
import com.google.android.gms.internal.mlkit_vision_barcode.B7;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3409x1;
import com.google.android.gms.internal.mlkit_vision_document_scanner.O4;
import com.quizlet.ads.ui.fragments.NativeAdFragment;
import com.quizlet.ads.ui.fragments.OutStreamVideoAdFragment;
import com.quizlet.ads.ui.fragments.StaticBannerAdFragment;
import com.quizlet.ads.ui.fragments.VerticalVideoAdFragment;
import com.quizlet.ads.ui.widgets.AdsCountDownButton;
import com.quizlet.data.model.C0;
import com.quizlet.data.model.Chapter;
import com.quizlet.data.model.D0;
import com.quizlet.data.model.E0;
import com.quizlet.data.model.J1;
import com.quizlet.data.model.TableOfContents;
import com.quizlet.data.model.Textbook;
import com.quizlet.data.model.k2;
import com.quizlet.eventlogger.features.explanations.ExplanationsLogger;
import com.quizlet.eventlogger.model.ExplanationsEventLog;
import com.quizlet.explanations.textbook.exercisedetail.ui.ExerciseDetailFragment;
import com.quizlet.explanations.textbook.tableofcontents.ui.TableOfContentsFragment;
import com.quizlet.explanations.textbook.ui.TextbookFragment;
import com.quizlet.generated.enums.y1;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.ui.globalnav.data.GlobalNavSuiteItem$Home;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final /* synthetic */ class U implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;

    public /* synthetic */ U(int i, Object obj, Object obj2) {
        this.a = i;
        this.b = obj;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        boolean z;
        com.google.android.gms.ads.s sVarA;
        com.google.android.gms.ads.s sVarA2;
        com.quizlet.explanations.textbook.data.u uVar;
        String str;
        String studyMaterialId = "";
        int i = 5;
        boolean z2 = false;
        int i2 = 1;
        Object obj2 = this.b;
        switch (this.a) {
            case 0:
                C1291m backStackEntry = (C1291m) obj;
                Intrinsics.checkNotNullParameter(backStackEntry, "backStackEntry");
                B b = backStackEntry.b;
                if (b == null) {
                    b = null;
                }
                if (b != null) {
                    androidx.navigation.internal.c cVar = backStackEntry.h;
                    cVar.a();
                    W w = (W) obj2;
                    B bC = w.c(b);
                    if (bC != null) {
                        return bC.equals(b) ? backStackEntry : w.b().b(bC, bC.b(cVar.a()));
                    }
                }
                return null;
            case 1:
                B startDestination = (B) obj;
                Intrinsics.checkNotNullParameter(startDestination, "startDestination");
                Map mapH = startDestination.h();
                LinkedHashMap linkedHashMap = new LinkedHashMap(kotlin.collections.U.a(mapH.size()));
                for (Map.Entry entry : mapH.entrySet()) {
                    linkedHashMap.put(entry.getKey(), ((C1289k) entry.getValue()).a);
                }
                return androidx.navigation.serialization.d.c((GlobalNavSuiteItem$Home) obj2, linkedHashMap);
            case 2:
                ((coil3.disk.e) obj2).l = true;
                return Unit.a;
            case 3:
                if (obj == null) {
                    return BrazeGeofenceManager.requestSingleLocationUpdateFromGooglePlay$lambda$42((BrazeGeofenceManager) obj2, null);
                }
                throw new ClassCastException();
            case 4:
                if (obj == null) {
                    return C1498k.a((C1498k) obj2, null);
                }
                throw new ClassCastException();
            case 5:
                return h0.a((h0) obj2, (String) obj);
            case 6:
                return UserJavascriptInterfaceBase.setGender$lambda$4((Gender) obj2, (BrazeUser) obj);
            case 7:
                return RemoveFromCustomAttributeArrayStep.run$lambda$1((StepData) obj2, (BrazeUser) obj);
            case 8:
                androidx.constraintlayout.core.widgets.analyzer.f fVar = (androidx.constraintlayout.core.widgets.analyzer.f) obj2;
                if (!((Boolean) obj).booleanValue()) {
                    System.out.println((Object) "[PerimeterX] Failed to load the Doctor App's assets. Please follow the instructions in the integration guide: https://docs.perimeterx.com/pxconsole/docs/android-how-to-verify-the-integration-in-your-app-with-the-sdk-v3)");
                    com.perimeterx.mobile_sdk.doctor_app.e action = com.perimeterx.mobile_sdk.doctor_app.e.l;
                    Intrinsics.checkNotNullParameter(action, "action");
                    fVar.a(new com.perimeterx.mobile_sdk.doctor_app.model.a(action));
                }
                new Handler(Looper.getMainLooper()).post(new com.perimeterx.mobile_sdk.doctor_app.c(fVar, i2));
                return Unit.a;
            case 9:
                return Boolean.valueOf(Intrinsics.b(((com.perimeterx.mobile_sdk.session.d) obj).b.a, ((com.perimeterx.mobile_sdk.session.d) obj2).b.a));
            case 10:
                NativeAdFragment nativeAdFragment = (NativeAdFragment) obj2;
                com.quizlet.ads.g gVar = nativeAdFragment.k;
                if (gVar == null) {
                    Intrinsics.m("adsRepository");
                    throw null;
                }
                NativeCustomFormatAd nativeCustomFormatAd = gVar.a;
                if (nativeCustomFormatAd != null) {
                    com.quizlet.ads.databinding.b bVar = (com.quizlet.ads.databinding.b) nativeAdFragment.J();
                    CharSequence text = nativeCustomFormatAd.getText("Headline");
                    if (text != null) {
                        bVar.b.setText(text);
                    }
                    CharSequence text2 = nativeCustomFormatAd.getText("Description");
                    if (text2 != null) {
                        bVar.d.setText(text2);
                    }
                    CharSequence text3 = nativeCustomFormatAd.getText("CallToAction");
                    if (text3 == null) {
                        text3 = nativeCustomFormatAd.getText("Calltoaction");
                    }
                    if (text3 != null) {
                        ((com.quizlet.ads.databinding.b) nativeAdFragment.J()).f.setText(text3.toString());
                    }
                    CharSequence text4 = nativeCustomFormatAd.getText("AdvertiserName");
                    if (text4 == null) {
                        text4 = nativeCustomFormatAd.getText("Advertiser");
                    }
                    if (text4 != null) {
                        com.quizlet.ads.databinding.b bVar2 = (com.quizlet.ads.databinding.b) nativeAdFragment.J();
                        String upperCase = text4.toString().toUpperCase(Locale.ROOT);
                        Intrinsics.checkNotNullExpressionValue(upperCase, "toUpperCase(...)");
                        bVar2.e.setText(upperCase);
                    }
                    com.google.android.gms.ads.nativead.c image = nativeCustomFormatAd.getImage("Image");
                    if (image != null) {
                        bVar.c.setImageDrawable(((C2568rb) image).b);
                        Unit unit = Unit.a;
                    }
                    ((com.quizlet.ads.databinding.b) nativeAdFragment.J()).f.setOnClickListener(new com.braze.ui.inappmessage.d(nativeCustomFormatAd, 12));
                    com.google.android.gms.ads.m mediaContent = nativeCustomFormatAd.getMediaContent();
                    if (mediaContent == null || !((F0) mediaContent).b()) {
                        z = false;
                    } else {
                        androidx.constraintlayout.widget.o oVar = new androidx.constraintlayout.widget.o();
                        oVar.d(((com.quizlet.ads.databinding.b) nativeAdFragment.J()).g);
                        int id = ((com.quizlet.ads.databinding.b) nativeAdFragment.J()).e.getId();
                        int id2 = ((com.quizlet.ads.databinding.b) nativeAdFragment.J()).h.getId();
                        HashMap map = oVar.d;
                        if (!map.containsKey(Integer.valueOf(id))) {
                            map.put(Integer.valueOf(id), new androidx.constraintlayout.widget.j());
                        }
                        androidx.constraintlayout.widget.j jVar = (androidx.constraintlayout.widget.j) map.get(Integer.valueOf(id));
                        if (jVar != null) {
                            androidx.constraintlayout.widget.k kVar = jVar.d;
                            kVar.n = id2;
                            kVar.m = -1;
                            kVar.q = -1;
                            kVar.r = -1;
                            kVar.s = -1;
                        }
                        oVar.a(((com.quizlet.ads.databinding.b) nativeAdFragment.J()).g);
                        AppCompatImageView adImage = ((com.quizlet.ads.databinding.b) nativeAdFragment.J()).c;
                        Intrinsics.checkNotNullExpressionValue(adImage, "adImage");
                        adImage.setVisibility(4);
                        FrameLayout mediaViewFrame = ((com.quizlet.ads.databinding.b) nativeAdFragment.J()).h;
                        Intrinsics.checkNotNullExpressionValue(mediaViewFrame, "mediaViewFrame");
                        AbstractC3188k6.c(mediaViewFrame);
                        FrameLayout mediaViewFrame2 = ((com.quizlet.ads.databinding.b) nativeAdFragment.J()).h;
                        Intrinsics.checkNotNullExpressionValue(mediaViewFrame2, "mediaViewFrame");
                        z = false;
                        mediaViewFrame2.setVisibility(0);
                    }
                    FrameLayout frameLayout = ((com.quizlet.ads.databinding.b) nativeAdFragment.J()).h;
                    AbstractC3188k6.c(frameLayout);
                    com.google.android.gms.ads.m mediaContent2 = nativeCustomFormatAd.getMediaContent();
                    if (mediaContent2 != null) {
                        com.quizlet.ads.ui.fragments.a aVar = nativeAdFragment.l;
                        if (aVar == null) {
                            Intrinsics.m("mediaViewCreator");
                            throw null;
                        }
                        frameLayout.addView((View) aVar.a(mediaContent2));
                    }
                    nativeCustomFormatAd.recordImpression();
                    com.quizlet.data.repository.folderwithcreatorinclass.e eVar = nativeAdFragment.j;
                    ((com.quizlet.ads.viewmodel.a) eVar.getValue()).C(O4.a(nativeCustomFormatAd));
                    com.quizlet.ads.viewmodel.a aVar2 = (com.quizlet.ads.viewmodel.a) eVar.getValue();
                    com.google.android.gms.ads.m mediaContent3 = nativeCustomFormatAd.getMediaContent();
                    boolean z3 = (mediaContent3 == null || (sVarA = ((F0) mediaContent3).a()) == null || !sVarA.a()) ? z : true;
                    androidx.lifecycle.Y y = aVar2.j;
                    if (z3) {
                        y.j(new com.quizlet.ads.ui.widgets.b());
                    } else {
                        y.j(new com.quizlet.ads.ui.widgets.c());
                    }
                }
                return Unit.a;
            case 11:
                String str2 = OutStreamVideoAdFragment.m;
                OutStreamVideoAdFragment outStreamVideoAdFragment = (OutStreamVideoAdFragment) obj2;
                ((com.quizlet.ads.databinding.c) outStreamVideoAdFragment.J()).b.setText(((com.quizlet.ads.data.f) obj).a);
                com.quizlet.ads.g gVar2 = outStreamVideoAdFragment.k;
                if (gVar2 == null) {
                    Intrinsics.m("adsRepository");
                    throw null;
                }
                NativeCustomFormatAd nativeCustomFormatAd2 = gVar2.a;
                if (nativeCustomFormatAd2 != null) {
                    nativeCustomFormatAd2.recordImpression();
                    com.quizlet.data.repository.folderwithcreatorinclass.e eVar2 = outStreamVideoAdFragment.j;
                    com.quizlet.ads.viewmodel.a aVar3 = (com.quizlet.ads.viewmodel.a) eVar2.getValue();
                    com.google.android.gms.ads.m mediaContent4 = nativeCustomFormatAd2.getMediaContent();
                    if (mediaContent4 == null || (sVarA2 = ((F0) mediaContent4).a()) == null || !sVarA2.a()) {
                        aVar3.B();
                    } else {
                        aVar3.getClass();
                    }
                    ((com.quizlet.ads.viewmodel.a) eVar2.getValue()).C(O4.a(nativeCustomFormatAd2));
                    com.google.android.gms.ads.m mediaContent5 = nativeCustomFormatAd2.getMediaContent();
                    if (mediaContent5 != null && ((F0) mediaContent5).b()) {
                        com.quizlet.ads.ui.fragments.a aVar4 = outStreamVideoAdFragment.l;
                        if (aVar4 == null) {
                            Intrinsics.m("mediaViewCreator");
                            throw null;
                        }
                        com.google.android.gms.ads.nativead.b bVar3 = (com.google.android.gms.ads.nativead.b) aVar4.a(mediaContent5);
                        FrameLayout videoContainer = ((com.quizlet.ads.databinding.c) outStreamVideoAdFragment.J()).c;
                        Intrinsics.checkNotNullExpressionValue(videoContainer, "videoContainer");
                        AbstractC3188k6.c(videoContainer);
                        videoContainer.setVisibility(0);
                        if (bVar3.getParent() != null) {
                            ViewParent parent = bVar3.getParent();
                            Intrinsics.e(parent, "null cannot be cast to non-null type android.view.ViewGroup");
                            ((ViewGroup) parent).removeView(bVar3);
                        }
                        ((com.quizlet.ads.databinding.c) outStreamVideoAdFragment.J()).c.addView(bVar3);
                    }
                }
                return Unit.a;
            case 12:
                String str3 = StaticBannerAdFragment.l;
                StaticBannerAdFragment staticBannerAdFragment = (StaticBannerAdFragment) obj2;
                FrameLayout adContainer = ((com.quizlet.ads.databinding.d) staticBannerAdFragment.J()).b;
                Intrinsics.checkNotNullExpressionValue(adContainer, "adContainer");
                AbstractC3188k6.c(adContainer);
                com.quizlet.ads.g gVar3 = staticBannerAdFragment.k;
                if (gVar3 == null) {
                    Intrinsics.m("adsRepository");
                    throw null;
                }
                AdManagerAdView adManagerAdView = gVar3.b;
                if ((adManagerAdView != null ? adManagerAdView.getParent() : null) != null) {
                    ViewParent parent2 = adManagerAdView.getParent();
                    Intrinsics.e(parent2, "null cannot be cast to non-null type android.view.ViewGroup");
                    ((ViewGroup) parent2).removeView(adManagerAdView);
                }
                com.quizlet.ads.databinding.d dVar = (com.quizlet.ads.databinding.d) staticBannerAdFragment.J();
                com.quizlet.ads.g gVar4 = staticBannerAdFragment.k;
                if (gVar4 != null) {
                    dVar.b.addView(gVar4.b);
                    return Unit.a;
                }
                Intrinsics.m("adsRepository");
                throw null;
            case 13:
                com.quizlet.ads.data.i iVar = (com.quizlet.ads.data.i) obj;
                String str4 = VerticalVideoAdFragment.m;
                VerticalVideoAdFragment verticalVideoAdFragment = (VerticalVideoAdFragment) obj2;
                if (Intrinsics.b(iVar, com.quizlet.ads.data.h.a)) {
                    FrameLayout videoContainer2 = ((com.quizlet.ads.databinding.e) verticalVideoAdFragment.J()).b;
                    Intrinsics.checkNotNullExpressionValue(videoContainer2, "videoContainer");
                    verticalVideoAdFragment.U(videoContainer2);
                    Unit unit2 = Unit.a;
                    verticalVideoAdFragment.T(R.id.videoContainer, R.dimen.ref_spacing_xsmall);
                } else {
                    if (!Intrinsics.b(iVar, com.quizlet.ads.data.h.b)) {
                        throw new NoWhenBranchMatchedException();
                    }
                    FrameLayout videoContainer916 = ((com.quizlet.ads.databinding.e) verticalVideoAdFragment.J()).c;
                    Intrinsics.checkNotNullExpressionValue(videoContainer916, "videoContainer916");
                    verticalVideoAdFragment.U(videoContainer916);
                    Unit unit3 = Unit.a;
                    verticalVideoAdFragment.T(R.id.videoContainer916, R.dimen.ref_spacing_large);
                    ((com.quizlet.ads.databinding.e) verticalVideoAdFragment.J()).c.setClipToOutline(true);
                }
                return Unit.a;
            case 14:
                long jLongValue = ((Long) obj).longValue();
                int i3 = AdsCountDownButton.B;
                AdsCountDownButton adsCountDownButton = (AdsCountDownButton) obj2;
                String string = adsCountDownButton.getContext().getString(R.string.learn_ads_button_count_down, Long.valueOf((jLongValue / 1000) + 1));
                Intrinsics.checkNotNullExpressionValue(string, "getString(...)");
                adsCountDownButton.setText(string);
                return Unit.a;
            case 15:
                androidx.compose.ui.graphics.S graphicsLayer = (androidx.compose.ui.graphics.S) obj;
                Intrinsics.checkNotNullParameter(graphicsLayer, "$this$graphicsLayer");
                if (((com.quizlet.assembly.compose.components.flashcards.d) obj2) == com.quizlet.assembly.compose.components.flashcards.d.a) {
                    graphicsLayer.h(180.0f);
                } else {
                    graphicsLayer.i(180.0f);
                }
                return Unit.a;
            case 16:
                ExplanationsEventLog.Payload createEvent = (ExplanationsEventLog.Payload) obj;
                int i4 = ExplanationsLogger.a;
                Intrinsics.checkNotNullParameter(createEvent, "$this$createEvent");
                createEvent.setPlacement(((ExplanationsLogger.MeteringPlacement) obj2).getLoggingName());
                return Unit.a;
            case 17:
                com.quizlet.explanations.myexplanations.data.l it2 = (com.quizlet.explanations.myexplanations.data.l) obj;
                Intrinsics.checkNotNullParameter(it2, "it");
                if (!(it2 instanceof com.quizlet.explanations.myexplanations.data.j)) {
                    return it2;
                }
                com.quizlet.explanations.myexplanations.data.j jVar2 = (com.quizlet.explanations.myexplanations.data.j) it2;
                kotlinx.collections.immutable.b list = AbstractC3409x1.i(CollectionsKt.p0(jVar2.b, ((com.quizlet.explanations.myexplanations.viewmodel.m) obj2).i));
                kotlinx.collections.immutable.b header = jVar2.a;
                Intrinsics.checkNotNullParameter(header, "header");
                Intrinsics.checkNotNullParameter(list, "list");
                return new com.quizlet.explanations.myexplanations.data.j(header, list);
            case 18:
                Throwable it3 = (Throwable) obj;
                Intrinsics.checkNotNullParameter(it3, "it");
                timber.log.c.a.f(it3, "Failed to save Question (" + ((C0) obj2) + ") to My Explanations", new Object[0]);
                return Unit.a;
            case 19:
                com.quizlet.explanations.solution.recyclerview.step.c it4 = (com.quizlet.explanations.solution.recyclerview.step.c) obj;
                Intrinsics.checkNotNullParameter(it4, "it");
                it4.b = false;
                com.quizlet.explanations.solution.recyclerview.step.k kVar2 = (com.quizlet.explanations.solution.recyclerview.step.k) obj2;
                kVar2.e.f.j(Integer.valueOf(kVar2.getBindingAdapterPosition()));
                return Unit.a;
            case 20:
                com.quizlet.explanations.textbook.exercisedetail.data.a aVar5 = (com.quizlet.explanations.textbook.exercisedetail.data.a) obj;
                String str5 = ExerciseDetailFragment.y;
                if (!(aVar5 instanceof com.quizlet.explanations.textbook.exercisedetail.data.a)) {
                    throw new NoWhenBranchMatchedException();
                }
                ((com.quizlet.explanations.textbook.viewmodel.c) ((ExerciseDetailFragment) obj2).u.getValue()).C(aVar5.a, aVar5.b);
                return Unit.a;
            case 21:
                Throwable it5 = (Throwable) obj;
                Intrinsics.checkNotNullParameter(it5, "it");
                timber.log.c.a.f(it5, "Failed to save Exercise (" + ((E0) obj2) + ") to My Explanations", new Object[0]);
                return Unit.a;
            case EventType.WINDOW_STATE /* 22 */:
                Textbook textbook = (Textbook) obj;
                String str6 = TableOfContentsFragment.p;
                com.quizlet.explanations.textbook.viewmodel.c cVarT = ((TableOfContentsFragment) obj2).T();
                Intrinsics.d(textbook);
                String screenName = TextbookFragment.l;
                cVarT.getClass();
                Intrinsics.checkNotNullParameter(textbook, "textbook");
                Intrinsics.checkNotNullParameter(screenName, "screenName");
                cVarT.m = textbook;
                cVarT.c.d(screenName, new ExplanationsLogger.EventData.Textbook(textbook.a, textbook.b));
                cVarT.n.clear();
                androidx.lifecycle.Y y2 = cVarT.i;
                com.quizlet.explanations.textbook.data.u uVar2 = (com.quizlet.explanations.textbook.data.u) y2.d();
                if (uVar2 != null) {
                    Textbook textbook2 = cVarT.m;
                    if (textbook2 != null && (str = textbook2.b) != null) {
                        studyMaterialId = str;
                    }
                    Intrinsics.checkNotNullParameter(studyMaterialId, "studyMaterialId");
                    y1 studyMaterialType = uVar2.d;
                    Intrinsics.checkNotNullParameter(studyMaterialType, "studyMaterialType");
                    uVar = new com.quizlet.explanations.textbook.data.u(uVar2.a, uVar2.b, studyMaterialId, studyMaterialType);
                } else {
                    uVar = null;
                }
                y2.j(uVar);
                return Unit.a;
            case EventType.AUDIO /* 23 */:
                kotlin.v vVar = (kotlin.v) obj;
                Intrinsics.checkNotNullParameter(vVar, "<destruct>");
                Object obj3 = vVar.a;
                Intrinsics.checkNotNullExpressionValue(obj3, "component1(...)");
                k2 k2Var = (k2) obj3;
                Object obj4 = vVar.b;
                Intrinsics.checkNotNullExpressionValue(obj4, "component2(...)");
                Object obj5 = vVar.c;
                Intrinsics.checkNotNullExpressionValue(obj5, "component3(...)");
                boolean zBooleanValue = ((Boolean) obj5).booleanValue();
                boolean zBooleanValue2 = ((Boolean) obj4).booleanValue();
                com.quizlet.explanations.textbook.tableofcontents.viewmodel.b bVar4 = (com.quizlet.explanations.textbook.tableofcontents.viewmodel.b) obj2;
                Textbook textbook3 = k2Var.a;
                bVar4.i.j(textbook3);
                bVar4.g.getClass();
                long jA = com.quizlet.time.b.a();
                Intrinsics.checkNotNullParameter(textbook3, "<this>");
                D0 d0 = new D0(textbook3.a, textbook3.b, textbook3.c, textbook3.d, textbook3.e, textbook3.f, jA, textbook3.g, textbook3.h);
                io.reactivex.rxjava3.internal.operators.completable.a aVar6 = new io.reactivex.rxjava3.internal.operators.completable.a(5, bVar4.f.n(), new androidx.compose.foundation.text.input.internal.u(bVar4, z2, d0, 18));
                Intrinsics.checkNotNullExpressionValue(aVar6, "flatMapCompletable(...)");
                io.reactivex.rxjava3.disposables.b bVarC = B7.c(aVar6, new U(d0, 24), null, 2);
                Intrinsics.checkNotNullParameter(bVarC, "<this>");
                bVar4.A(bVarC);
                androidx.lifecycle.Y y3 = bVar4.j;
                Intrinsics.checkNotNullParameter(k2Var, "<this>");
                Textbook textbook4 = k2Var.a;
                String str7 = textbook4.d;
                String str8 = textbook4.e;
                String str9 = textbook4.h;
                String str10 = textbook4.b;
                String str11 = textbook4.c;
                y3.j(zBooleanValue ? new com.quizlet.explanations.textbook.data.b(str11, str8, str9, "ISBN: " + str10, str7, textbook4.f, zBooleanValue2, k2Var.b) : new com.quizlet.explanations.textbook.data.a(str11, str8, str9, "ISBN: " + str10, str7, textbook4.f, zBooleanValue2, k2Var.b));
                TableOfContents tableOfContents = new TableOfContents(textbook3.l);
                if (textbook3.g <= 0) {
                    tableOfContents = null;
                }
                List list2 = tableOfContents != null ? tableOfContents.a : null;
                if (list2 == null) {
                    list2 = TableOfContents.b;
                }
                ArrayList arrayList = new ArrayList();
                ArrayList arrayList2 = new ArrayList();
                for (Object obj6 : list2) {
                    if (obj6 instanceof Chapter) {
                        arrayList2.add(obj6);
                    }
                }
                Iterator it6 = arrayList2.iterator();
                while (it6.hasNext()) {
                    Chapter chapter = (Chapter) it6.next();
                    com.quizlet.explanations.solution.fragments.b onClick = new com.quizlet.explanations.solution.fragments.b(1, bVar4, com.quizlet.explanations.textbook.tableofcontents.viewmodel.b.class, "goToChapterMenu", "goToChapterMenu(Lcom/quizlet/data/model/TableOfContentItem;)V", 0, 26);
                    Intrinsics.checkNotNullParameter(chapter, "<this>");
                    Intrinsics.checkNotNullParameter(onClick, "onClick");
                    long j = chapter.a;
                    String str12 = chapter.d;
                    String str13 = str12 == null ? "" : str12;
                    String str14 = chapter.c;
                    arrayList.add(new com.quizlet.explanations.textbook.tableofcontents.recyclerview.d(j, str13, str14 == null ? "" : str14, chapter.b, chapter, onClick));
                }
                if (!arrayList.isEmpty()) {
                    arrayList.add(0, com.quizlet.explanations.textbook.tableofcontents.recyclerview.b.a);
                }
                bVar4.k.j(arrayList);
                return Unit.a;
            case EventType.VIDEO /* 24 */:
                Throwable it7 = (Throwable) obj;
                Intrinsics.checkNotNullParameter(it7, "it");
                timber.log.c.a.f(it7, "Failed to save Textbook (" + ((D0) obj2) + ") to My Explanations", new Object[0]);
                return Unit.a;
            case EventType.SUBS /* 25 */:
                com.facebook.i result = (com.facebook.i) obj;
                Intrinsics.checkNotNullParameter(result, "result");
                int i5 = result.b;
                ((C1553h) ((com.facebook.j) obj2)).a(i5, i5, result.c);
                return Unit.a;
            case EventType.CDN /* 26 */:
                androidx.compose.foundation.lazy.g LazyRow = (androidx.compose.foundation.lazy.g) obj;
                Intrinsics.checkNotNullParameter(LazyRow, "$this$LazyRow");
                kotlinx.collections.immutable.b bVar5 = (kotlinx.collections.immutable.b) obj2;
                LazyRow.q(bVar5.size(), null, new com.quizlet.assembly.compose.menu.e(bVar5, 3), new androidx.compose.runtime.internal.d(true, -632812321, new com.quizlet.features.achievements.ui.composables.l(bVar5, i2)));
                return Unit.a;
            case 27:
                androidx.compose.foundation.lazy.grid.i LazyVerticalGrid = (androidx.compose.foundation.lazy.grid.i) obj;
                Intrinsics.checkNotNullParameter(LazyVerticalGrid, "$this$LazyVerticalGrid");
                ArrayList arrayList3 = ((J1) obj2).c;
                LazyVerticalGrid.p(arrayList3.size(), null, null, new C0293u(6, arrayList3), new androidx.compose.runtime.internal.d(true, 699646206, new androidx.compose.foundation.lazy.f(arrayList3, i)));
                return Unit.a;
            case 28:
                com.quizlet.assembly.compose.modals.x.d((com.quizlet.assembly.compose.modals.x) obj2);
                return Unit.a;
            default:
                com.quizlet.ui.models.content.listitem.o it8 = (com.quizlet.ui.models.content.listitem.o) obj;
                Intrinsics.checkNotNullParameter(it8, "it");
                com.quizlet.features.folders.addtofolder.data.s sVar = (com.quizlet.features.folders.addtofolder.data.s) obj2;
                if (Intrinsics.b(it8.d(), sVar.a.d()) && it8.b() == sVar.a.b()) {
                    z2 = true;
                }
                return Boolean.valueOf(z2);
        }
    }

    public /* synthetic */ U(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }
}
