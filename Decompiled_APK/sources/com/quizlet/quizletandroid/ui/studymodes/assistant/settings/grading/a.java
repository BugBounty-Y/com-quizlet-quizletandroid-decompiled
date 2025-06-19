package com.quizlet.quizletandroid.ui.studymodes.assistant.settings.grading;

import android.os.Parcelable;
import androidx.compose.foundation.lazy.A;
import androidx.compose.foundation.lazy.r;
import androidx.compose.runtime.C0776c;
import com.comscore.streaming.EventType;
import com.google.android.gms.internal.mlkit_vision_camera.T1;
import com.quizlet.eventlogger.EventLogger;
import com.quizlet.eventlogger.features.studymodes.StudyModeEventLogger;
import com.quizlet.generated.enums.A1;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.ui.studymodes.assistant.settings.grading.data.LearnSettingsGradingUpdateData;
import com.quizlet.quizletandroid.ui.studymodes.assistant.settings.grading.data.g;
import com.quizlet.quizletandroid.ui.studymodes.match.activity.MatchActivity;
import com.quizlet.quizletandroid.ui.studymodes.match.fragment.DiagramMatchGameFragment;
import com.quizlet.quizletandroid.ui.studymodes.match.fragment.MatchStartGameFragment;
import com.quizlet.quizletandroid.ui.studymodes.match.fragment.StandardMatchGameFragment;
import com.quizlet.quizletandroid.ui.studymodes.testmode.activities.TestStudyModeActivity;
import com.quizlet.report.data.o;
import com.quizlet.richtext.model.PmDocument;
import com.quizlet.uicommon.ui.common.dialogs.UnstyledConvertibleModalDialogFragment;
import com.quizlet.uicommon.ui.common.overflowmenu.FullscreenOverflowFragment;
import com.quizlet.upgrade.data.UpgradePackage;
import com.quizlet.upgrade.ui.confirmation.UpgradeConfirmationFragment;
import com.quizlet.upgrade.ui.fragment.TermsAndConditionsModalFragment;
import com.quizlet.upgrade.ui.fragment.UpgradeFragment;
import com.quizlet.upgrade.ui.fragment.UpgradePlansModalFragment;
import com.quizlet.upgrade.viewmodel.h;
import com.skydoves.balloon.Balloon;
import io.ktor.client.plugins.C4861h;
import io.ktor.utils.io.n;
import java.io.File;
import java.io.InputStream;
import java.net.URI;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.concurrent.atomic.AtomicReference;
import kotlin.Pair;
import kotlin.Unit;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.D;
import kotlin.text.StringsKt;
import kotlinx.coroutines.C5027k0;
import kotlinx.coroutines.O;
import kotlinx.coroutines.scheduling.e;
import kotlinx.serialization.descriptors.SerialDescriptor;
import kotlinx.serialization.internal.AbstractC5047c0;
import okio.t;
import okio.x;

/* loaded from: classes3.dex */
public final /* synthetic */ class a implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;

    public /* synthetic */ a(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    /* JADX WARN: Type inference failed for: r0v18, types: [java.lang.Object, java.util.List] */
    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        int iQ;
        Pair pair;
        Pair pair2;
        Object obj = this.b;
        switch (this.a) {
            case 0:
                g gVar = (g) obj;
                return C0776c.z(new LearnSettingsGradingUpdateData(gVar.a, gVar.b, gVar.c));
            case 1:
                String str = MatchActivity.s;
                ((MatchActivity) obj).f0(true);
                return Unit.a;
            case 2:
                String str2 = DiagramMatchGameFragment.t;
                return ((DiagramMatchGameFragment) obj).requireActivity().getDefaultViewModelCreationExtras();
            case 3:
                String str3 = MatchStartGameFragment.n;
                return ((MatchStartGameFragment) obj).requireActivity().getDefaultViewModelCreationExtras();
            case 4:
                String str4 = StandardMatchGameFragment.r;
                return ((StandardMatchGameFragment) obj).requireActivity().getDefaultViewModelCreationExtras();
            case 5:
                return new StudyModeEventLogger((EventLogger) ((com.onetrust.otpublishers.headless.UI.TVUI.datautils.a) obj).b, A1.MOBILE_SCATTER);
            case 6:
                com.onetrust.otpublishers.headless.UI.viewmodel.c cVar = ((TestStudyModeActivity) obj).q;
                if (cVar != null) {
                    return cVar;
                }
                Intrinsics.m("viewModelFactory");
                throw null;
            case 7:
                r rVar = (r) CollectionsKt.V(((A) obj).h().j);
                return Integer.valueOf(rVar != null ? rVar.a + 1 : 0);
            case 8:
                return C0776c.z(((o) obj).b);
            case 9:
                return ((com.quizlet.richtext.parser.a) obj).a.a(PmDocument.class, com.squareup.moshi.internal.b.a, null);
            case 10:
                return Boolean.valueOf(((UnstyledConvertibleModalDialogFragment) obj).getResources().getConfiguration().smallestScreenWidthDp < 600);
            case 11:
                ((FullscreenOverflowFragment) obj).G();
                return Unit.a;
            case 12:
                String str5 = UpgradeConfirmationFragment.l;
                Parcelable parcelable = ((UpgradeConfirmationFragment) obj).requireArguments().getParcelable("upgradePackage");
                Intrinsics.e(parcelable, "null cannot be cast to non-null type com.quizlet.upgrade.data.UpgradePackage");
                return (UpgradePackage) parcelable;
            case 13:
                String str6 = TermsAndConditionsModalFragment.V;
                return ((TermsAndConditionsModalFragment) obj).getString(R.string.terms_and_conditions);
            case 14:
                String str7 = UpgradeFragment.r;
                return Boolean.valueOf(((UpgradeFragment) obj).requireArguments().getBoolean("fromGlobalNav", false));
            case 15:
                String str8 = UpgradePlansModalFragment.W;
                return ((UpgradePlansModalFragment) obj).getString(R.string.choose_your_plan_title);
            case 16:
                Boolean bool = (Boolean) ((h) obj).c.a("isAfterSignUp");
                return Boolean.valueOf(bool != null ? bool.booleanValue() : false);
            case 17:
                return Balloon.Builder.runIfReachedShowCounts$lambda$165$lambda$164((Runnable) obj);
            case 18:
                C4861h c4861h = (C4861h) ((io.ktor.http.content.c) obj);
                switch (c4861h.a) {
                    case 0:
                        return (n) c4861h.d;
                    default:
                        InputStream inputStream = (InputStream) c4861h.d;
                        e eVar = O.a;
                        kotlinx.coroutines.scheduling.d context = kotlinx.coroutines.scheduling.d.b;
                        io.ktor.utils.io.pool.a pool = io.ktor.utils.io.pool.b.a;
                        Intrinsics.checkNotNullParameter(inputStream, "<this>");
                        Intrinsics.checkNotNullParameter(context, "context");
                        Intrinsics.checkNotNullParameter(pool, "pool");
                        Intrinsics.checkNotNullParameter(inputStream, "<this>");
                        return new io.ktor.utils.io.jvm.javaio.d(new kotlinx.io.b(inputStream), context);
                }
            case 19:
                ((C5027k0) obj).k0();
                return Unit.a;
            case 20:
                return ((io.ktor.client.plugins.internal.d) obj).a();
            case 21:
                io.reactivex.rxjava3.disposables.b bVar = (io.reactivex.rxjava3.disposables.b) ((AtomicReference) obj).getAndSet(io.reactivex.rxjava3.internal.disposables.b.a);
                if (bVar != null) {
                    bVar.dispose();
                }
                return Unit.a;
            case EventType.WINDOW_STATE /* 22 */:
                kotlinx.serialization.c cVar2 = (kotlinx.serialization.c) obj;
                kotlinx.serialization.descriptors.g gVarG = T1.g("kotlinx.serialization.Polymorphic", kotlinx.serialization.descriptors.c.b, new SerialDescriptor[0], new com.quizlet.ui.compose.modifiers.b(cVar2, 15));
                kotlin.reflect.c context2 = cVar2.a;
                Intrinsics.checkNotNullParameter(gVarG, "<this>");
                Intrinsics.checkNotNullParameter(context2, "context");
                return new kotlinx.serialization.descriptors.b(gVarG, context2);
            case EventType.AUDIO /* 23 */:
                kotlinx.serialization.descriptors.g gVar2 = (kotlinx.serialization.descriptors.g) obj;
                return Integer.valueOf(AbstractC5047c0.f(gVar2, gVar2.k));
            default:
                okio.internal.g gVar3 = (okio.internal.g) obj;
                ClassLoader classLoader = gVar3.c;
                Enumeration<URL> resources = classLoader.getResources("");
                Intrinsics.checkNotNullExpressionValue(resources, "getResources(...)");
                ArrayList list = Collections.list(resources);
                Intrinsics.checkNotNullExpressionValue(list, "list(...)");
                ArrayList arrayList = new ArrayList();
                Iterator it2 = list.iterator();
                while (true) {
                    boolean zHasNext = it2.hasNext();
                    t tVar = gVar3.d;
                    if (!zHasNext) {
                        Enumeration<URL> resources2 = classLoader.getResources("META-INF/MANIFEST.MF");
                        Intrinsics.checkNotNullExpressionValue(resources2, "getResources(...)");
                        ArrayList<URL> list2 = Collections.list(resources2);
                        Intrinsics.checkNotNullExpressionValue(list2, "list(...)");
                        ArrayList arrayList2 = new ArrayList();
                        for (URL url : list2) {
                            Intrinsics.d(url);
                            String string = url.toString();
                            Intrinsics.checkNotNullExpressionValue(string, "toString(...)");
                            if (D.r(string, "jar:file:", false) && (iQ = StringsKt.Q(string, "!", 0, 6)) != -1) {
                                String str9 = x.b;
                                String strSubstring = string.substring(4, iQ);
                                Intrinsics.checkNotNullExpressionValue(strSubstring, "substring(...)");
                                File file = new File(URI.create(strSubstring));
                                Intrinsics.checkNotNullParameter(file, "<this>");
                                String string2 = file.toString();
                                Intrinsics.checkNotNullExpressionValue(string2, "toString(...)");
                                pair = new Pair(okio.internal.b.e(com.quizlet.quizletandroid.ui.folder.logging.a.f(string2, false), tVar, new com.sdk.growthbook.utils.a(28)), okio.internal.g.f);
                            } else {
                                pair = null;
                            }
                            if (pair != null) {
                                arrayList2.add(pair);
                            }
                        }
                        return CollectionsKt.c0(arrayList, arrayList2);
                    }
                    URL url2 = (URL) it2.next();
                    Intrinsics.d(url2);
                    if (Intrinsics.b(url2.getProtocol(), "file")) {
                        String str10 = x.b;
                        File file2 = new File(url2.toURI());
                        Intrinsics.checkNotNullParameter(file2, "<this>");
                        String string3 = file2.toString();
                        Intrinsics.checkNotNullExpressionValue(string3, "toString(...)");
                        pair2 = new Pair(tVar, com.quizlet.quizletandroid.ui.folder.logging.a.f(string3, false));
                    } else {
                        pair2 = null;
                    }
                    if (pair2 != null) {
                        arrayList.add(pair2);
                    }
                }
                break;
        }
    }
}
