package androidx.navigation.internal;

import android.content.Context;
import android.os.Bundle;
import android.view.ViewGroup;
import android.webkit.WebSettings;
import android.webkit.WebView;
import androidx.compose.animation.C0293u;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.runtime.snapshots.t;
import androidx.compose.ui.platform.N;
import androidx.compose.ui.q;
import androidx.navigation.C1291m;
import com.braze.enums.CardKey;
import com.braze.managers.C1500m;
import com.braze.storage.ICardStorageProvider;
import com.quizlet.features.flashcards.C4237k;
import com.quizlet.features.folders.composables.V;
import com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels.C4759a;
import com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels.C4760b;
import com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels.I;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import kotlin.Unit;
import kotlin.collections.K;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.F;
import kotlin.jvm.internal.H;
import kotlin.jvm.internal.Intrinsics;
import org.json.JSONArray;

/* loaded from: classes.dex */
public final /* synthetic */ class i implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;
    public final /* synthetic */ Object c;
    public final /* synthetic */ Object d;
    public final /* synthetic */ Object e;
    public final /* synthetic */ Object f;

    public /* synthetic */ i(Object obj, Object obj2, Object obj3, Object obj4, Object obj5, int i) {
        this.a = i;
        this.b = obj;
        this.c = obj2;
        this.d = obj3;
        this.e = obj4;
        this.f = obj5;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        List listSubList;
        switch (this.a) {
            case 0:
                C1291m entry = (C1291m) obj;
                Intrinsics.checkNotNullParameter(entry, "entry");
                ((F) this.b).a = true;
                ArrayList arrayList = (ArrayList) this.c;
                int iIndexOf = arrayList.indexOf(entry);
                if (iIndexOf != -1) {
                    H h = (H) this.d;
                    int i = iIndexOf + 1;
                    listSubList = arrayList.subList(h.a, i);
                    h.a = i;
                } else {
                    listSubList = K.a;
                }
                ((j) this.e).a(entry.b, (Bundle) this.f, entry, listSubList);
                return Unit.a;
            case 1:
                JSONArray jSONArray = (JSONArray) this.f;
                return com.braze.models.g.a((CardKey.Provider) this.b, (C1500m) this.c, (ICardStorageProvider) this.d, (com.braze.analytics.c) this.e, jSONArray, obj);
            case 2:
                androidx.compose.foundation.lazy.g LazyColumn = (androidx.compose.foundation.lazy.g) obj;
                Intrinsics.checkNotNullParameter(LazyColumn, "$this$LazyColumn");
                C4237k c4237k = new C4237k(20);
                kotlinx.collections.immutable.b bVar = (kotlinx.collections.immutable.b) this.b;
                LazyColumn.q(bVar.size(), new androidx.compose.ui.viewinterop.b(16, c4237k, bVar), new com.quizlet.assembly.compose.menu.e(bVar, 7), new androidx.compose.runtime.internal.d(true, -632812321, new com.quizlet.features.infra.folder.menu.composable.j(bVar, (kotlinx.collections.immutable.c) this.c, (t) this.d, (Function2) this.e, (Function1) this.f)));
                return Unit.a;
            case 3:
                androidx.compose.foundation.lazy.g LazyColumn2 = (androidx.compose.foundation.lazy.g) obj;
                Intrinsics.checkNotNullParameter(LazyColumn2, "$this$LazyColumn");
                androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
                com.quizlet.themes.m mVar = com.quizlet.themes.m.g;
                mVar.t();
                q qVarG = N.G(AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.k, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), "motivational_message_section");
                List list = ((C4759a) this.b).a;
                LazyColumn2.q(list.size(), null, new com.quizlet.assembly.compose.menu.e(list, 19), new androidx.compose.runtime.internal.d(true, -632812321, new com.quizlet.quizletandroid.ui.studymodes.testmode.compose.l(list, qVarG, 0)));
                float f = com.quizlet.quizletandroid.ui.studymodes.testmode.compose.m.a;
                q qVarG2 = N.G(AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, f, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), "results_section");
                List list2 = ((I) this.c).a;
                LazyColumn2.q(list2.size(), null, new com.quizlet.assembly.compose.menu.e(list2, 21), new androidx.compose.runtime.internal.d(true, -632812321, new com.quizlet.quizletandroid.ui.studymodes.testmode.compose.l(list2, qVarG2, 2)));
                q qVarG3 = N.G(AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, f, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), "next_step_section");
                List list3 = ((C4760b) this.d).a;
                LazyColumn2.q(list3.size(), null, new com.quizlet.assembly.compose.menu.e(list3, 20), new androidx.compose.runtime.internal.d(true, -632812321, new com.quizlet.quizletandroid.ui.studymodes.testmode.compose.l(list3, qVarG3, 1)));
                com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.composables.l lVar = new com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.composables.l(27, (Function1) this.f);
                mVar.q();
                q qVarG4 = N.G(AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.i, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), "answers_section_header");
                q qVarY = AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, f, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13);
                List list4 = ((com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels.H) this.e).a;
                ArrayList arrayList2 = new ArrayList();
                for (Object obj2 : list4) {
                    if (obj2 instanceof com.quizlet.quizletandroid.ui.studymodes.testmode.models.t) {
                        arrayList2.add(obj2);
                    }
                }
                if (!arrayList2.isEmpty()) {
                    androidx.compose.foundation.lazy.g.p(LazyColumn2, null, new androidx.compose.runtime.internal.d(true, 1777304649, new com.quizlet.baseui.base.d(qVarG4, 15)), 3);
                    LazyColumn2.q(arrayList2.size(), null, new C0293u(8, arrayList2), new androidx.compose.runtime.internal.d(true, -632812321, new V((List) arrayList2, (Object) qVarY, (Object) lVar, 6)));
                    androidx.compose.foundation.lazy.g.p(LazyColumn2, null, com.quizlet.quizletandroid.ui.studymodes.testmode.compose.b.a, 3);
                }
                return Unit.a;
            default:
                Context context = (Context) obj;
                Intrinsics.checkNotNullParameter(context, "context");
                WebView webView = new WebView(context);
                webView.setLayoutParams(new ViewGroup.LayoutParams(-1, -1));
                webView.setWebViewClient((com.quizlet.security.challenge.ui.a) this.b);
                WebSettings settings = webView.getSettings();
                Intrinsics.checkNotNullExpressionValue(settings, "getSettings(...)");
                settings.setJavaScriptEnabled(true);
                settings.setUserAgentString((String) this.c);
                webView.addJavascriptInterface((com.quizlet.security.challenge.viewmodel.a) this.d, "androidCfChallenge");
                webView.setLayerType(1, null);
                webView.loadUrl((String) this.e, (Map) this.f);
                return webView;
        }
    }
}
