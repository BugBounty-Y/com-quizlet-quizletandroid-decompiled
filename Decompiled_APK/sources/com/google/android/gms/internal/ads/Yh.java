package com.google.android.gms.internal.ads;

import android.animation.Animator;
import android.animation.AnimatorSet;
import android.animation.ValueAnimator;
import android.graphics.Rect;
import android.graphics.drawable.Drawable;
import android.net.Uri;
import android.view.View;
import android.view.ViewGroup;
import android.view.animation.Interpolator;
import android.view.animation.LinearInterpolator;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.ImageButton;
import android.widget.TextView;
import androidx.appcompat.widget.ActionMenuView;
import androidx.appcompat.widget.Toolbar;
import com.google.android.gms.internal.ads.Yh;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3179j6;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3633h4;
import com.google.android.material.appbar.MaterialToolbar;
import com.google.android.material.internal.ClippableRoundedCornerLayout;
import com.google.android.material.internal.TouchObserverFrameLayout;
import com.google.android.material.search.SearchBar;
import com.google.android.material.search.SearchView;
import com.quizlet.api.IQuizletApiClient;
import com.quizlet.eventlogger.EventLogger;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.HashSet;
import java.util.List;
import java.util.WeakHashMap;
import java.util.concurrent.Executor;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class Yh {
    public final /* synthetic */ int a;
    public Object b;
    public Object c;
    public Object d;
    public Object e;
    public Object f;
    public Object g;
    public Object h;
    public Object i;
    public Object j;
    public Object k;
    public Object l;
    public Object m;
    public Object n;
    public Object o;
    public Object p;

    public Yh(int i) {
        this.a = i;
        switch (i) {
            case 2:
                this.g = new androidx.navigation.internal.m();
                this.h = new androidx.navigation.internal.m();
                this.i = new androidx.navigation.internal.m();
                this.j = new androidx.compose.runtime.internal.j();
                this.l = new androidx.navigation.internal.m();
                this.m = new androidx.navigation.internal.m();
                this.n = new androidx.constraintlayout.motion.widget.n();
                this.o = new androidx.camera.camera2.internal.compat.workaround.b();
                this.p = new io.ktor.client.plugins.api.d(9);
                break;
            default:
                this.b = new HashSet();
                this.c = new HashSet();
                this.d = new HashSet();
                this.e = new HashSet();
                this.f = new HashSet();
                this.g = new HashSet();
                this.h = new HashSet();
                this.i = new HashSet();
                this.j = new HashSet();
                this.k = new HashSet();
                this.l = new HashSet();
                this.m = new HashSet();
                this.n = new HashSet();
                this.o = new HashSet();
                break;
        }
    }

    public static void a(Yh yh, float f) {
        ActionMenuView actionMenuViewH;
        ((ImageButton) yh.k).setAlpha(f);
        ((View) yh.l).setAlpha(f);
        ((TouchObserverFrameLayout) yh.m).setAlpha(f);
        if (!((SearchView) yh.b).w || (actionMenuViewH = com.google.android.material.internal.p.h((MaterialToolbar) yh.g)) == null) {
            return;
        }
        actionMenuViewH.setAlpha(f);
    }

    public static boolean l(Uri uri, List list) {
        List list2 = com.quizlet.quizletandroid.managers.deeplinks.w.c;
        String host = uri.getHost();
        if (host == null) {
            host = "";
        }
        if (list2.contains(host)) {
            return true;
        }
        List list3 = com.quizlet.quizletandroid.managers.deeplinks.w.d;
        String str = (String) CollectionsKt.firstOrNull(list);
        return list3.contains(str != null ? str : "");
    }

    public void b(AnimatorSet animatorSet) {
        ImageButton imageButtonI = com.google.android.material.internal.p.i((MaterialToolbar) this.g);
        if (imageButtonI == null) {
            return;
        }
        Drawable drawableE = AbstractC3179j6.e(imageButtonI.getDrawable());
        if (!((SearchView) this.b).v) {
            if (drawableE instanceof androidx.appcompat.graphics.drawable.a) {
                androidx.appcompat.graphics.drawable.a aVar = (androidx.appcompat.graphics.drawable.a) drawableE;
                if (aVar.i != 1.0f) {
                    aVar.i = 1.0f;
                    aVar.invalidateSelf();
                }
            }
            if (drawableE instanceof com.google.android.material.internal.d) {
                ((com.google.android.material.internal.d) drawableE).a(1.0f);
                return;
            }
            return;
        }
        if (drawableE instanceof androidx.appcompat.graphics.drawable.a) {
            ValueAnimator valueAnimatorOfFloat = ValueAnimator.ofFloat(DefinitionKt.NO_Float_VALUE, 1.0f);
            valueAnimatorOfFloat.addUpdateListener(new com.airbnb.lottie.s((androidx.appcompat.graphics.drawable.a) drawableE, 3));
            animatorSet.playTogether(valueAnimatorOfFloat);
        }
        if (drawableE instanceof com.google.android.material.internal.d) {
            ValueAnimator valueAnimatorOfFloat2 = ValueAnimator.ofFloat(DefinitionKt.NO_Float_VALUE, 1.0f);
            valueAnimatorOfFloat2.addUpdateListener(new com.airbnb.lottie.s((com.google.android.material.internal.d) drawableE, 4));
            animatorSet.playTogether(valueAnimatorOfFloat2);
        }
    }

    public AnimatorSet c(boolean z) {
        int i = 18;
        AnimatorSet animatorSet = new AnimatorSet();
        MaterialToolbar materialToolbar = (MaterialToolbar) this.g;
        ImageButton imageButtonI = com.google.android.material.internal.p.i(materialToolbar);
        if (imageButtonI != null) {
            ValueAnimator valueAnimatorOfFloat = ValueAnimator.ofFloat(f(imageButtonI), DefinitionKt.NO_Float_VALUE);
            valueAnimatorOfFloat.addUpdateListener(new androidx.swiperefreshlayout.widget.b(new com.facebook.appevents.k(i), new View[]{imageButtonI}));
            ValueAnimator valueAnimatorOfFloat2 = ValueAnimator.ofFloat(g(), DefinitionKt.NO_Float_VALUE);
            valueAnimatorOfFloat2.addUpdateListener(androidx.swiperefreshlayout.widget.b.a(imageButtonI));
            animatorSet.playTogether(valueAnimatorOfFloat, valueAnimatorOfFloat2);
        }
        ActionMenuView actionMenuViewH = com.google.android.material.internal.p.h(materialToolbar);
        if (actionMenuViewH != null) {
            ValueAnimator valueAnimatorOfFloat3 = ValueAnimator.ofFloat(e(actionMenuViewH), DefinitionKt.NO_Float_VALUE);
            valueAnimatorOfFloat3.addUpdateListener(new androidx.swiperefreshlayout.widget.b(new com.facebook.appevents.k(i), new View[]{actionMenuViewH}));
            ValueAnimator valueAnimatorOfFloat4 = ValueAnimator.ofFloat(g(), DefinitionKt.NO_Float_VALUE);
            valueAnimatorOfFloat4.addUpdateListener(androidx.swiperefreshlayout.widget.b.a(actionMenuViewH));
            animatorSet.playTogether(valueAnimatorOfFloat3, valueAnimatorOfFloat4);
        }
        animatorSet.setDuration(z ? 300L : 250L);
        animatorSet.setInterpolator(com.google.android.material.internal.j.a(z, com.google.android.material.animation.a.b));
        return animatorSet;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r16v0 */
    /* JADX WARN: Type inference failed for: r16v1 */
    /* JADX WARN: Type inference failed for: r16v3 */
    /* JADX WARN: Type inference failed for: r23v0, types: [com.google.android.gms.internal.ads.Yh] */
    /* JADX WARN: Type inference failed for: r7v0, types: [android.animation.Animator, android.animation.AnimatorSet] */
    public AnimatorSet d(boolean z) {
        float f;
        ?? r16;
        int i = 21;
        ?? animatorSet = new AnimatorSet();
        if (((AnimatorSet) this.o) == null) {
            AnimatorSet animatorSet2 = new AnimatorSet();
            b(animatorSet2);
            animatorSet2.setDuration(z ? 300L : 250L);
            animatorSet2.setInterpolator(com.google.android.material.internal.j.a(z, com.google.android.material.animation.a.b));
            animatorSet.playTogether(animatorSet2, c(z));
        }
        Interpolator interpolator = z ? com.google.android.material.animation.a.a : com.google.android.material.animation.a.b;
        ValueAnimator valueAnimatorOfFloat = ValueAnimator.ofFloat(DefinitionKt.NO_Float_VALUE, 1.0f);
        valueAnimatorOfFloat.setDuration(z ? 300L : 250L);
        valueAnimatorOfFloat.setInterpolator(com.google.android.material.internal.j.a(z, interpolator));
        valueAnimatorOfFloat.addUpdateListener(new androidx.swiperefreshlayout.widget.b(new com.facebook.appevents.k(i), new View[]{(View) this.c}));
        com.google.android.material.motion.g gVar = (com.google.android.material.motion.g) this.n;
        Rect rect = gVar.j;
        Rect rectB = gVar.k;
        SearchView searchView = (SearchView) this.b;
        if (rect != null) {
            r16 = 0;
            f = DefinitionKt.NO_Float_VALUE;
        } else {
            int left = searchView.getLeft();
            f = DefinitionKt.NO_Float_VALUE;
            r16 = 0;
            rect = new Rect(left, searchView.getTop(), searchView.getRight(), searchView.getBottom());
        }
        ClippableRoundedCornerLayout clippableRoundedCornerLayout = (ClippableRoundedCornerLayout) this.d;
        if (rectB == null) {
            rectB = com.google.android.material.internal.p.b(clippableRoundedCornerLayout, (SearchBar) this.p);
        }
        final Rect rect2 = new Rect(rectB);
        final float cornerSize = ((SearchBar) this.p).getCornerSize();
        final float fMax = Math.max(clippableRoundedCornerLayout.getCornerRadius(), gVar.c());
        ValueAnimator valueAnimatorOfObject = ValueAnimator.ofObject(new com.google.android.material.floatingactionbutton.m(rect2), rectB, rect);
        valueAnimatorOfObject.addUpdateListener(new ValueAnimator.AnimatorUpdateListener() { // from class: com.google.android.material.search.i
            @Override // android.animation.ValueAnimator.AnimatorUpdateListener
            public final void onAnimationUpdate(ValueAnimator valueAnimator) {
                Yh yh = this.a;
                yh.getClass();
                float fA = com.google.android.material.animation.a.a(cornerSize, fMax, valueAnimator.getAnimatedFraction());
                ClippableRoundedCornerLayout clippableRoundedCornerLayout2 = (ClippableRoundedCornerLayout) yh.d;
                clippableRoundedCornerLayout2.getClass();
                Rect rect3 = rect2;
                clippableRoundedCornerLayout2.a(rect3.left, rect3.top, rect3.right, rect3.bottom, fA);
            }
        });
        valueAnimatorOfObject.setDuration(z ? 300L : 250L);
        androidx.interpolator.view.animation.a aVar = com.google.android.material.animation.a.b;
        valueAnimatorOfObject.setInterpolator(com.google.android.material.internal.j.a(z, aVar));
        ValueAnimator valueAnimatorOfFloat2 = ValueAnimator.ofFloat(DefinitionKt.NO_Float_VALUE, 1.0f);
        valueAnimatorOfFloat2.setDuration(z ? 50L : 42L);
        valueAnimatorOfFloat2.setStartDelay(z ? 250L : 0L);
        LinearInterpolator linearInterpolator = com.google.android.material.animation.a.a;
        valueAnimatorOfFloat2.setInterpolator(com.google.android.material.internal.j.a(z, linearInterpolator));
        View[] viewArr = new View[1];
        viewArr[r16] = (ImageButton) this.k;
        valueAnimatorOfFloat2.addUpdateListener(new androidx.swiperefreshlayout.widget.b(new com.facebook.appevents.k(i), viewArr));
        AnimatorSet animatorSet3 = new AnimatorSet();
        ValueAnimator valueAnimatorOfFloat3 = ValueAnimator.ofFloat(DefinitionKt.NO_Float_VALUE, 1.0f);
        valueAnimatorOfFloat3.setDuration(z ? 150L : 83L);
        valueAnimatorOfFloat3.setStartDelay(z ? 75L : 0L);
        valueAnimatorOfFloat3.setInterpolator(com.google.android.material.internal.j.a(z, linearInterpolator));
        View view = (View) this.l;
        TouchObserverFrameLayout touchObserverFrameLayout = (TouchObserverFrameLayout) this.m;
        View[] viewArr2 = new View[2];
        viewArr2[r16] = view;
        viewArr2[1] = touchObserverFrameLayout;
        valueAnimatorOfFloat3.addUpdateListener(new androidx.swiperefreshlayout.widget.b(new com.facebook.appevents.k(i), viewArr2));
        float[] fArr = new float[2];
        fArr[r16] = (touchObserverFrameLayout.getHeight() * 0.050000012f) / 2.0f;
        fArr[1] = f;
        ValueAnimator valueAnimatorOfFloat4 = ValueAnimator.ofFloat(fArr);
        valueAnimatorOfFloat4.setDuration(z ? 300L : 250L);
        valueAnimatorOfFloat4.setInterpolator(com.google.android.material.internal.j.a(z, aVar));
        valueAnimatorOfFloat4.addUpdateListener(androidx.swiperefreshlayout.widget.b.a(view));
        ValueAnimator valueAnimatorOfFloat5 = ValueAnimator.ofFloat(0.95f, 1.0f);
        valueAnimatorOfFloat5.setDuration(z ? 300L : 250L);
        valueAnimatorOfFloat5.setInterpolator(com.google.android.material.internal.j.a(z, aVar));
        View[] viewArr3 = new View[1];
        viewArr3[r16] = touchObserverFrameLayout;
        valueAnimatorOfFloat5.addUpdateListener(new androidx.swiperefreshlayout.widget.b(new com.facebook.appevents.k(20), viewArr3));
        Animator[] animatorArr = new Animator[3];
        animatorArr[r16] = valueAnimatorOfFloat3;
        animatorArr[1] = valueAnimatorOfFloat4;
        animatorArr[2] = valueAnimatorOfFloat5;
        animatorSet3.playTogether(animatorArr);
        boolean z2 = r16;
        AnimatorSet animatorSetI = i(z, z2, (FrameLayout) this.e);
        Toolbar toolbar = (Toolbar) this.h;
        AnimatorSet animatorSetI2 = i(z, z2, toolbar);
        ValueAnimator valueAnimatorOfFloat6 = ValueAnimator.ofFloat(DefinitionKt.NO_Float_VALUE, 1.0f);
        valueAnimatorOfFloat6.setDuration(z ? 300L : 250L);
        valueAnimatorOfFloat6.setInterpolator(com.google.android.material.internal.j.a(z, aVar));
        if (searchView.w) {
            valueAnimatorOfFloat6.addUpdateListener(new com.google.android.material.internal.e(com.google.android.material.internal.p.h(toolbar), com.google.android.material.internal.p.h((MaterialToolbar) this.g)));
        }
        animatorSet.playTogether(valueAnimatorOfFloat, valueAnimatorOfObject, valueAnimatorOfFloat2, animatorSet3, animatorSetI, animatorSetI2, valueAnimatorOfFloat6, i(z, true, (EditText) this.j), i(z, true, (TextView) this.i));
        animatorSet.addListener(new androidx.appcompat.widget.S0((Yh) this, z));
        return animatorSet;
    }

    public int e(View view) {
        int marginEnd = ((ViewGroup.MarginLayoutParams) view.getLayoutParams()).getMarginEnd();
        return com.google.android.material.internal.p.k((SearchBar) this.p) ? ((SearchBar) this.p).getLeft() - marginEnd : (((SearchBar) this.p).getRight() - ((SearchView) this.b).getWidth()) + marginEnd;
    }

    public int f(View view) {
        int marginStart = ((ViewGroup.MarginLayoutParams) view.getLayoutParams()).getMarginStart();
        SearchBar searchBar = (SearchBar) this.p;
        WeakHashMap weakHashMap = androidx.core.view.V.a;
        int paddingStart = searchBar.getPaddingStart();
        return com.google.android.material.internal.p.k((SearchBar) this.p) ? ((((SearchBar) this.p).getWidth() - ((SearchBar) this.p).getRight()) + marginStart) - paddingStart : (((SearchBar) this.p).getLeft() - marginStart) + paddingStart;
    }

    public int g() {
        FrameLayout frameLayout = (FrameLayout) this.f;
        return ((((SearchBar) this.p).getBottom() + ((SearchBar) this.p).getTop()) / 2) - ((frameLayout.getBottom() + frameLayout.getTop()) / 2);
    }

    public AnimatorSet h(boolean z) {
        AnimatorSet animatorSet = new AnimatorSet();
        ClippableRoundedCornerLayout clippableRoundedCornerLayout = (ClippableRoundedCornerLayout) this.d;
        ValueAnimator valueAnimatorOfFloat = ValueAnimator.ofFloat(clippableRoundedCornerLayout.getHeight(), DefinitionKt.NO_Float_VALUE);
        valueAnimatorOfFloat.addUpdateListener(androidx.swiperefreshlayout.widget.b.a(clippableRoundedCornerLayout));
        animatorSet.playTogether(valueAnimatorOfFloat);
        b(animatorSet);
        animatorSet.setInterpolator(com.google.android.material.internal.j.a(z, com.google.android.material.animation.a.b));
        animatorSet.setDuration(z ? 350L : 300L);
        return animatorSet;
    }

    public AnimatorSet i(boolean z, boolean z2, View view) {
        ValueAnimator valueAnimatorOfFloat = ValueAnimator.ofFloat(z2 ? f(view) : e(view), DefinitionKt.NO_Float_VALUE);
        valueAnimatorOfFloat.addUpdateListener(new androidx.swiperefreshlayout.widget.b(new com.facebook.appevents.k(18), new View[]{view}));
        ValueAnimator valueAnimatorOfFloat2 = ValueAnimator.ofFloat(g(), DefinitionKt.NO_Float_VALUE);
        valueAnimatorOfFloat2.addUpdateListener(androidx.swiperefreshlayout.widget.b.a(view));
        AnimatorSet animatorSet = new AnimatorSet();
        animatorSet.playTogether(valueAnimatorOfFloat, valueAnimatorOfFloat2);
        animatorSet.setDuration(z ? 300L : 250L);
        animatorSet.setInterpolator(com.google.android.material.internal.j.a(z, com.google.android.material.animation.a.b));
        return animatorSet;
    }

    public void j(Uri uri, com.quizlet.quizletandroid.ui.deeplinkinterstitial.i iVar, com.quizlet.infra.androidcontracts.deeplink.a deepLink) {
        com.quizlet.quizletandroid.util.links.a.a((EventLogger) this.f, uri, deepLink.identity());
        iVar.getClass();
        Intrinsics.checkNotNullParameter(deepLink, "deepLink");
        kotlinx.coroutines.E.A(androidx.lifecycle.p0.j(iVar), null, null, new com.quizlet.quizletandroid.ui.deeplinkinterstitial.g(iVar, deepLink, null), 3);
    }

    public AnimatorSet k() {
        SearchBar searchBar = (SearchBar) this.p;
        SearchView searchView = (SearchView) this.b;
        if (searchBar != null) {
            if (searchView.g()) {
                searchView.f();
            }
            AnimatorSet animatorSetD = d(false);
            animatorSetD.addListener(new com.google.android.material.search.k(this, 1));
            animatorSetD.start();
            return animatorSetD;
        }
        if (searchView.g()) {
            searchView.f();
        }
        AnimatorSet animatorSetH = h(false);
        animatorSetH.addListener(new com.google.android.material.search.k(this, 3));
        animatorSetH.start();
        return animatorSetH;
    }

    public void m(InterfaceC1840ah interfaceC1840ah, Executor executor) {
        ((HashSet) this.j).add(new C2318li(interfaceC1840ah, executor));
    }

    public void n(Jh jh, Executor executor) {
        ((HashSet) this.c).add(new C2318li(jh, executor));
    }

    public void o(com.google.android.gms.ads.admanager.a aVar, Executor executor) {
        ((HashSet) this.l).add(new C2318li(aVar, executor));
    }

    public void p(InterfaceC2447oi interfaceC2447oi, Executor executor) {
        ((HashSet) this.e).add(new C2318li(interfaceC2447oi, executor));
    }

    public String toString() {
        switch (this.a) {
            case 2:
                StringBuilder sb = new StringBuilder("OTSDKListUIProperty{backgroundColor='");
                sb.append((String) this.b);
                sb.append("', lineBreakColor='");
                sb.append((String) this.c);
                sb.append("', filterOnColor='");
                sb.append((String) this.d);
                sb.append("', filterOffColor='");
                sb.append((String) this.e);
                sb.append("', summaryTitle=");
                AbstractC3633h4.a((androidx.navigation.internal.m) this.g, sb, ", summaryDescription=");
                AbstractC3633h4.a((androidx.navigation.internal.m) this.h, sb, ", searchBarProperty=");
                sb.append(((androidx.compose.runtime.internal.j) this.j).toString());
                sb.append(", filterList_SelectionColor='");
                sb.append((String) this.k);
                sb.append("', filterList_NavItem=");
                AbstractC3633h4.a((androidx.navigation.internal.m) this.l, sb, ", filterList_SDKItem=");
                AbstractC3633h4.a((androidx.navigation.internal.m) this.m, sb, ", backIconProperty=");
                sb.append(((androidx.camera.camera2.internal.compat.workaround.b) this.o).toString());
                sb.append(", filterIconProperty=");
                sb.append(((io.ktor.client.plugins.api.d) this.p).toString());
                sb.append('}');
                return sb.toString();
            default:
                return super.toString();
        }
    }

    public Yh(IQuizletApiClient apiClient, io.reactivex.rxjava3.core.o networkScheduler, io.reactivex.rxjava3.core.o mainThreadScheduler, com.quizlet.quizletandroid.config.b deepLinkBlocklist, EventLogger eventLogger, com.quizlet.utmhelper.c jsUtmHelper, com.quizlet.login.common.interactors.d deepLinkRouter, com.quizlet.quizletandroid.config.a deepLinkAllowlist, com.quizlet.quizletandroid.config.c marketingDeepLinkAllowlist, com.quizlet.quizletandroid.deeplinks.a setPageDeepLinkLookup, com.quizlet.quizletandroid.deeplinks.a explanationsDeepLinkLookup, com.quizlet.quizletandroid.deeplinks.a notesDeepLinkLookup, com.quizlet.login.common.interactors.d achievementsDeepLinkLookup, com.quizlet.quizletandroid.deeplinks.a practiceTestsDeepLinkLookup, com.quizlet.quizletandroid.t compositeDisposableProvider, com.quizlet.quizletandroid.managers.deeplinks.v practiceTestsUploadDeepLink) {
        this.a = 3;
        Intrinsics.checkNotNullParameter(apiClient, "apiClient");
        Intrinsics.checkNotNullParameter(networkScheduler, "networkScheduler");
        Intrinsics.checkNotNullParameter(mainThreadScheduler, "mainThreadScheduler");
        Intrinsics.checkNotNullParameter(deepLinkBlocklist, "deepLinkBlocklist");
        Intrinsics.checkNotNullParameter(eventLogger, "eventLogger");
        Intrinsics.checkNotNullParameter(jsUtmHelper, "jsUtmHelper");
        Intrinsics.checkNotNullParameter(deepLinkRouter, "deepLinkRouter");
        Intrinsics.checkNotNullParameter(deepLinkAllowlist, "deepLinkAllowlist");
        Intrinsics.checkNotNullParameter(marketingDeepLinkAllowlist, "marketingDeepLinkAllowlist");
        Intrinsics.checkNotNullParameter(setPageDeepLinkLookup, "setPageDeepLinkLookup");
        Intrinsics.checkNotNullParameter(explanationsDeepLinkLookup, "explanationsDeepLinkLookup");
        Intrinsics.checkNotNullParameter(notesDeepLinkLookup, "notesDeepLinkLookup");
        Intrinsics.checkNotNullParameter(achievementsDeepLinkLookup, "achievementsDeepLinkLookup");
        Intrinsics.checkNotNullParameter(practiceTestsDeepLinkLookup, "practiceTestsDeepLinkLookup");
        Intrinsics.checkNotNullParameter(compositeDisposableProvider, "compositeDisposableProvider");
        Intrinsics.checkNotNullParameter(practiceTestsUploadDeepLink, "practiceTestsUploadDeepLink");
        this.b = apiClient;
        this.c = networkScheduler;
        this.d = mainThreadScheduler;
        this.e = deepLinkBlocklist;
        this.f = eventLogger;
        this.g = jsUtmHelper;
        this.h = deepLinkRouter;
        this.i = deepLinkAllowlist;
        this.j = marketingDeepLinkAllowlist;
        this.k = setPageDeepLinkLookup;
        this.l = explanationsDeepLinkLookup;
        this.m = achievementsDeepLinkLookup;
        this.n = compositeDisposableProvider;
        this.o = practiceTestsUploadDeepLink;
        this.p = kotlin.l.b(new com.quizlet.login.magiclink.ui.e(this, 5));
    }

    public Yh(SearchView searchView) {
        this.a = 1;
        this.b = searchView;
        this.c = searchView.a;
        ClippableRoundedCornerLayout clippableRoundedCornerLayout = searchView.b;
        this.d = clippableRoundedCornerLayout;
        this.e = searchView.e;
        this.f = searchView.f;
        this.g = searchView.g;
        this.h = searchView.h;
        this.i = searchView.i;
        this.j = searchView.j;
        this.k = searchView.k;
        this.l = searchView.l;
        this.m = searchView.m;
        this.n = new com.google.android.material.motion.g(clippableRoundedCornerLayout);
    }
}
