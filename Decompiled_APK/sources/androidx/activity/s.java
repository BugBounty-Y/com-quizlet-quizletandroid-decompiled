package androidx.activity;

import android.app.Application;
import android.content.Intent;
import android.content.IntentSender;
import android.content.res.Configuration;
import android.os.Bundle;
import android.os.Trace;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import androidx.compose.ui.platform.C0978y0;
import androidx.core.app.AbstractActivityC1021h;
import androidx.core.app.C1023j;
import androidx.core.app.S;
import androidx.core.view.C1057n;
import androidx.core.view.InterfaceC1056m;
import androidx.core.view.InterfaceC1058o;
import androidx.fragment.app.W;
import androidx.lifecycle.B0;
import androidx.lifecycle.C0;
import androidx.lifecycle.C1247h;
import androidx.lifecycle.InterfaceC1261w;
import androidx.lifecycle.j0;
import androidx.lifecycle.l0;
import androidx.lifecycle.p0;
import androidx.lifecycle.x0;
import androidx.lifecycle.y0;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3347h2;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3359k2;
import com.quizlet.quizletandroid.R;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import kotlin.InterfaceC4935d;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes.dex */
public abstract class s extends AbstractActivityC1021h implements C0, InterfaceC1261w, androidx.savedstate.f, N, androidx.activity.result.i, androidx.core.content.f, androidx.core.content.g, androidx.core.app.O, androidx.core.app.P, InterfaceC1056m {

    @NotNull
    private static final C0038j Companion = new C0038j();
    private B0 _viewModelStore;

    @NotNull
    private final androidx.activity.result.h activityResultRegistry;
    private int contentLayoutId;

    @NotNull
    private final kotlin.k defaultViewModelProviderFactory$delegate;
    private boolean dispatchingOnMultiWindowModeChanged;
    private boolean dispatchingOnPictureInPictureModeChanged;

    @NotNull
    private final kotlin.k fullyDrawnReporter$delegate;

    @NotNull
    private final AtomicInteger nextLocalRequestCode;

    @NotNull
    private final kotlin.k onBackPressedDispatcher$delegate;

    @NotNull
    private final CopyOnWriteArrayList<androidx.core.util.a> onConfigurationChangedListeners;

    @NotNull
    private final CopyOnWriteArrayList<androidx.core.util.a> onMultiWindowModeChangedListeners;

    @NotNull
    private final CopyOnWriteArrayList<androidx.core.util.a> onNewIntentListeners;

    @NotNull
    private final CopyOnWriteArrayList<androidx.core.util.a> onPictureInPictureModeChangedListeners;

    @NotNull
    private final CopyOnWriteArrayList<androidx.core.util.a> onTrimMemoryListeners;

    @NotNull
    private final CopyOnWriteArrayList<Runnable> onUserLeaveHintListeners;

    @NotNull
    private final InterfaceExecutorC0040l reportFullyDrawnExecutor;

    @NotNull
    private final androidx.savedstate.e savedStateRegistryController;

    @NotNull
    private final androidx.activity.contextaware.a contextAwareHelper = new androidx.activity.contextaware.a();

    @NotNull
    private final C1057n menuHostHelper = new C1057n(new RunnableC0032d(this, 0));

    public s() {
        Intrinsics.checkNotNullParameter(this, "owner");
        C0978y0 c0978y0 = new C0978y0(this, new C1247h(this, 4));
        this.savedStateRegistryController = new androidx.savedstate.e(c0978y0);
        this.reportFullyDrawnExecutor = new ViewTreeObserverOnDrawListenerC0042n(this);
        this.fullyDrawnReporter$delegate = kotlin.l.b(new q(this, 2));
        this.nextLocalRequestCode = new AtomicInteger();
        this.activityResultRegistry = new C0044p(this);
        this.onConfigurationChangedListeners = new CopyOnWriteArrayList<>();
        this.onTrimMemoryListeners = new CopyOnWriteArrayList<>();
        this.onNewIntentListeners = new CopyOnWriteArrayList<>();
        this.onMultiWindowModeChangedListeners = new CopyOnWriteArrayList<>();
        this.onPictureInPictureModeChangedListeners = new CopyOnWriteArrayList<>();
        this.onUserLeaveHintListeners = new CopyOnWriteArrayList<>();
        if (getLifecycle() == null) {
            throw new IllegalStateException("getLifecycle() returned null in ComponentActivity's constructor. Please make sure you are lazily constructing your Lifecycle in the first call to getLifecycle() rather than relying on field initialization.");
        }
        final int i = 0;
        getLifecycle().a(new androidx.lifecycle.H(this) { // from class: androidx.activity.e
            public final /* synthetic */ s b;

            {
                this.b = this;
            }

            @Override // androidx.lifecycle.H
            public final void d(androidx.lifecycle.J j, androidx.lifecycle.A event) {
                Window window;
                View viewPeekDecorView;
                switch (i) {
                    case 0:
                        Intrinsics.checkNotNullParameter(j, "<anonymous parameter 0>");
                        Intrinsics.checkNotNullParameter(event, "event");
                        if (event == androidx.lifecycle.A.ON_STOP && (window = this.b.getWindow()) != null && (viewPeekDecorView = window.peekDecorView()) != null) {
                            viewPeekDecorView.cancelPendingInputEvents();
                            break;
                        }
                        break;
                    default:
                        s.m(this.b, j, event);
                        break;
                }
            }
        });
        final int i2 = 1;
        getLifecycle().a(new androidx.lifecycle.H(this) { // from class: androidx.activity.e
            public final /* synthetic */ s b;

            {
                this.b = this;
            }

            @Override // androidx.lifecycle.H
            public final void d(androidx.lifecycle.J j, androidx.lifecycle.A event) {
                Window window;
                View viewPeekDecorView;
                switch (i2) {
                    case 0:
                        Intrinsics.checkNotNullParameter(j, "<anonymous parameter 0>");
                        Intrinsics.checkNotNullParameter(event, "event");
                        if (event == androidx.lifecycle.A.ON_STOP && (window = this.b.getWindow()) != null && (viewPeekDecorView = window.peekDecorView()) != null) {
                            viewPeekDecorView.cancelPendingInputEvents();
                            break;
                        }
                        break;
                    default:
                        s.m(this.b, j, event);
                        break;
                }
            }
        });
        getLifecycle().a(new androidx.savedstate.a(this, i2));
        c0978y0.d();
        p0.d(this);
        getSavedStateRegistry().c("android:support:activity-result", new C0034f(this, 0));
        int i3 = 0;
        addOnContextAvailableListener(new C0035g(this, i3));
        this.defaultViewModelProviderFactory$delegate = kotlin.l.b(new q(this, i3));
        this.onBackPressedDispatcher$delegate = kotlin.l.b(new q(this, 3));
    }

    public static final void access$ensureViewModelStore(s sVar) {
        if (sVar._viewModelStore == null) {
            C0039k c0039k = (C0039k) sVar.getLastNonConfigurationInstance();
            if (c0039k != null) {
                sVar._viewModelStore = c0039k.b;
            }
            if (sVar._viewModelStore == null) {
                sVar._viewModelStore = new B0();
            }
        }
    }

    public static void l(s sVar, s it2) {
        Intrinsics.checkNotNullParameter(it2, "it");
        Bundle bundleA = sVar.getSavedStateRegistry().a("android:support:activity-result");
        if (bundleA != null) {
            androidx.activity.result.h hVar = sVar.activityResultRegistry;
            hVar.getClass();
            ArrayList<Integer> integerArrayList = bundleA.getIntegerArrayList("KEY_COMPONENT_ACTIVITY_REGISTERED_RCS");
            ArrayList<String> stringArrayList = bundleA.getStringArrayList("KEY_COMPONENT_ACTIVITY_REGISTERED_KEYS");
            if (stringArrayList == null || integerArrayList == null) {
                return;
            }
            ArrayList<String> stringArrayList2 = bundleA.getStringArrayList("KEY_COMPONENT_ACTIVITY_LAUNCHED_KEYS");
            if (stringArrayList2 != null) {
                hVar.d.addAll(stringArrayList2);
            }
            Bundle bundle = bundleA.getBundle("KEY_COMPONENT_ACTIVITY_PENDING_RESULT");
            Bundle bundle2 = hVar.g;
            if (bundle != null) {
                bundle2.putAll(bundle);
            }
            int size = stringArrayList.size();
            for (int i = 0; i < size; i++) {
                String str = stringArrayList.get(i);
                LinkedHashMap linkedHashMap = hVar.b;
                boolean zContainsKey = linkedHashMap.containsKey(str);
                LinkedHashMap linkedHashMap2 = hVar.a;
                if (zContainsKey) {
                    Integer num = (Integer) linkedHashMap.remove(str);
                    if (!bundle2.containsKey(str)) {
                        kotlin.jvm.internal.O.c(linkedHashMap2).remove(num);
                    }
                }
                Integer num2 = integerArrayList.get(i);
                Intrinsics.checkNotNullExpressionValue(num2, "rcs[i]");
                int iIntValue = num2.intValue();
                String str2 = stringArrayList.get(i);
                Intrinsics.checkNotNullExpressionValue(str2, "keys[i]");
                String str3 = str2;
                linkedHashMap2.put(Integer.valueOf(iIntValue), str3);
                linkedHashMap.put(str3, Integer.valueOf(iIntValue));
            }
        }
    }

    public static void m(s sVar, androidx.lifecycle.J j, androidx.lifecycle.A event) {
        Intrinsics.checkNotNullParameter(j, "<anonymous parameter 0>");
        Intrinsics.checkNotNullParameter(event, "event");
        if (event == androidx.lifecycle.A.ON_DESTROY) {
            sVar.contextAwareHelper.b = null;
            if (!sVar.isChangingConfigurations()) {
                sVar.getViewModelStore().a();
            }
            ViewTreeObserverOnDrawListenerC0042n viewTreeObserverOnDrawListenerC0042n = (ViewTreeObserverOnDrawListenerC0042n) sVar.reportFullyDrawnExecutor;
            s sVar2 = viewTreeObserverOnDrawListenerC0042n.d;
            sVar2.getWindow().getDecorView().removeCallbacks(viewTreeObserverOnDrawListenerC0042n);
            sVar2.getWindow().getDecorView().getViewTreeObserver().removeOnDrawListener(viewTreeObserverOnDrawListenerC0042n);
        }
    }

    public static Bundle n(s sVar) {
        Bundle outState = new Bundle();
        androidx.activity.result.h hVar = sVar.activityResultRegistry;
        hVar.getClass();
        Intrinsics.checkNotNullParameter(outState, "outState");
        LinkedHashMap linkedHashMap = hVar.b;
        outState.putIntegerArrayList("KEY_COMPONENT_ACTIVITY_REGISTERED_RCS", new ArrayList<>(linkedHashMap.values()));
        outState.putStringArrayList("KEY_COMPONENT_ACTIVITY_REGISTERED_KEYS", new ArrayList<>(linkedHashMap.keySet()));
        outState.putStringArrayList("KEY_COMPONENT_ACTIVITY_LAUNCHED_KEYS", new ArrayList<>(hVar.d));
        outState.putBundle("KEY_COMPONENT_ACTIVITY_PENDING_RESULT", new Bundle(hVar.g));
        return outState;
    }

    @Override // android.app.Activity
    public void addContentView(View view, ViewGroup.LayoutParams layoutParams) {
        initializeViewTreeOwners();
        InterfaceExecutorC0040l interfaceExecutorC0040l = this.reportFullyDrawnExecutor;
        View decorView = getWindow().getDecorView();
        Intrinsics.checkNotNullExpressionValue(decorView, "window.decorView");
        ((ViewTreeObserverOnDrawListenerC0042n) interfaceExecutorC0040l).a(decorView);
        super.addContentView(view, layoutParams);
    }

    @Override // androidx.core.view.InterfaceC1056m
    public void addMenuProvider(@NotNull InterfaceC1058o provider) {
        Intrinsics.checkNotNullParameter(provider, "provider");
        C1057n c1057n = this.menuHostHelper;
        c1057n.b.add(provider);
        c1057n.a.run();
    }

    @Override // androidx.core.content.f
    public final void addOnConfigurationChangedListener(@NotNull androidx.core.util.a listener) {
        Intrinsics.checkNotNullParameter(listener, "listener");
        this.onConfigurationChangedListeners.add(listener);
    }

    public final void addOnContextAvailableListener(@NotNull androidx.activity.contextaware.b listener) {
        Intrinsics.checkNotNullParameter(listener, "listener");
        androidx.activity.contextaware.a aVar = this.contextAwareHelper;
        aVar.getClass();
        Intrinsics.checkNotNullParameter(listener, "listener");
        s sVar = aVar.b;
        if (sVar != null) {
            listener.a(sVar);
        }
        aVar.a.add(listener);
    }

    @Override // androidx.core.app.O
    public final void addOnMultiWindowModeChangedListener(@NotNull androidx.core.util.a listener) {
        Intrinsics.checkNotNullParameter(listener, "listener");
        this.onMultiWindowModeChangedListeners.add(listener);
    }

    public final void addOnNewIntentListener(@NotNull androidx.core.util.a listener) {
        Intrinsics.checkNotNullParameter(listener, "listener");
        this.onNewIntentListeners.add(listener);
    }

    @Override // androidx.core.app.P
    public final void addOnPictureInPictureModeChangedListener(@NotNull androidx.core.util.a listener) {
        Intrinsics.checkNotNullParameter(listener, "listener");
        this.onPictureInPictureModeChangedListeners.add(listener);
    }

    @Override // androidx.core.content.g
    public final void addOnTrimMemoryListener(@NotNull androidx.core.util.a listener) {
        Intrinsics.checkNotNullParameter(listener, "listener");
        this.onTrimMemoryListeners.add(listener);
    }

    @Override // androidx.activity.result.i
    @NotNull
    public final androidx.activity.result.h getActivityResultRegistry() {
        return this.activityResultRegistry;
    }

    @Override // androidx.lifecycle.InterfaceC1261w
    @NotNull
    public androidx.lifecycle.viewmodel.c getDefaultViewModelCreationExtras() {
        androidx.lifecycle.viewmodel.e eVar = new androidx.lifecycle.viewmodel.e(0);
        if (getApplication() != null) {
            com.google.mlkit.common.sdkinternal.b bVar = x0.d;
            Application application = getApplication();
            Intrinsics.checkNotNullExpressionValue(application, "application");
            eVar.b(bVar, application);
        }
        eVar.b(p0.a, this);
        eVar.b(p0.b, this);
        Intent intent = getIntent();
        Bundle extras = intent != null ? intent.getExtras() : null;
        if (extras != null) {
            eVar.b(p0.c, extras);
        }
        return eVar;
    }

    @Override // androidx.lifecycle.InterfaceC1261w
    @NotNull
    public y0 getDefaultViewModelProviderFactory() {
        return (y0) this.defaultViewModelProviderFactory$delegate.getValue();
    }

    @NotNull
    public C getFullyDrawnReporter() {
        return (C) this.fullyDrawnReporter$delegate.getValue();
    }

    @Override // androidx.core.app.AbstractActivityC1021h, androidx.lifecycle.J
    @NotNull
    public androidx.lifecycle.C getLifecycle() {
        return super.getLifecycle();
    }

    @Override // androidx.activity.N
    @NotNull
    public final L getOnBackPressedDispatcher() {
        return (L) this.onBackPressedDispatcher$delegate.getValue();
    }

    @Override // androidx.savedstate.f
    @NotNull
    public final androidx.savedstate.d getSavedStateRegistry() {
        return this.savedStateRegistryController.b;
    }

    @Override // androidx.lifecycle.C0
    @NotNull
    public B0 getViewModelStore() {
        if (getApplication() == null) {
            throw new IllegalStateException("Your activity is not yet attached to the Application instance. You can't request ViewModel before onCreate call.");
        }
        if (this._viewModelStore == null) {
            C0039k c0039k = (C0039k) getLastNonConfigurationInstance();
            if (c0039k != null) {
                this._viewModelStore = c0039k.b;
            }
            if (this._viewModelStore == null) {
                this._viewModelStore = new B0();
            }
        }
        B0 b0 = this._viewModelStore;
        Intrinsics.d(b0);
        return b0;
    }

    public void initializeViewTreeOwners() {
        View decorView = getWindow().getDecorView();
        Intrinsics.checkNotNullExpressionValue(decorView, "window.decorView");
        p0.n(decorView, this);
        View decorView2 = getWindow().getDecorView();
        Intrinsics.checkNotNullExpressionValue(decorView2, "window.decorView");
        p0.o(decorView2, this);
        View decorView3 = getWindow().getDecorView();
        Intrinsics.checkNotNullExpressionValue(decorView3, "window.decorView");
        AbstractC3347h2.e(decorView3, this);
        View decorView4 = getWindow().getDecorView();
        Intrinsics.checkNotNullExpressionValue(decorView4, "window.decorView");
        androidx.camera.core.impl.utils.executor.i.d(decorView4, this);
        View decorView5 = getWindow().getDecorView();
        Intrinsics.checkNotNullExpressionValue(decorView5, "window.decorView");
        Intrinsics.checkNotNullParameter(decorView5, "<this>");
        Intrinsics.checkNotNullParameter(this, "fullyDrawnReporterOwner");
        decorView5.setTag(R.id.report_drawn, this);
    }

    public void invalidateMenu() {
        invalidateOptionsMenu();
    }

    @Override // android.app.Activity
    public void onActivityResult(int i, int i2, Intent intent) {
        if (this.activityResultRegistry.a(i, i2, intent)) {
            return;
        }
        super.onActivityResult(i, i2, intent);
    }

    @Override // android.app.Activity
    @InterfaceC4935d
    public void onBackPressed() {
        getOnBackPressedDispatcher().c();
    }

    @Override // android.app.Activity, android.content.ComponentCallbacks
    public void onConfigurationChanged(@NotNull Configuration newConfig) {
        Intrinsics.checkNotNullParameter(newConfig, "newConfig");
        super.onConfigurationChanged(newConfig);
        Iterator<androidx.core.util.a> it2 = this.onConfigurationChangedListeners.iterator();
        while (it2.hasNext()) {
            it2.next().accept(newConfig);
        }
    }

    @Override // androidx.core.app.AbstractActivityC1021h, android.app.Activity
    public void onCreate(Bundle bundle) {
        this.savedStateRegistryController.a(bundle);
        androidx.activity.contextaware.a aVar = this.contextAwareHelper;
        aVar.getClass();
        Intrinsics.checkNotNullParameter(this, "context");
        aVar.b = this;
        Iterator it2 = aVar.a.iterator();
        while (it2.hasNext()) {
            ((androidx.activity.contextaware.b) it2.next()).a(this);
        }
        super.onCreate(bundle);
        int i = l0.b;
        j0.b(this);
        int i2 = this.contentLayoutId;
        if (i2 != 0) {
            setContentView(i2);
        }
    }

    @Override // android.app.Activity, android.view.Window.Callback
    public boolean onCreatePanelMenu(int i, @NotNull Menu menu) {
        Intrinsics.checkNotNullParameter(menu, "menu");
        if (i != 0) {
            return true;
        }
        super.onCreatePanelMenu(i, menu);
        C1057n c1057n = this.menuHostHelper;
        MenuInflater menuInflater = getMenuInflater();
        Iterator it2 = c1057n.b.iterator();
        while (it2.hasNext()) {
            ((W) ((InterfaceC1058o) it2.next())).a.l(menu, menuInflater);
        }
        return true;
    }

    @Override // android.app.Activity, android.view.Window.Callback
    public boolean onMenuItemSelected(int i, MenuItem item) {
        Intrinsics.checkNotNullParameter(item, "item");
        if (super.onMenuItemSelected(i, item)) {
            return true;
        }
        if (i == 0) {
            return this.menuHostHelper.a(item);
        }
        return false;
    }

    @Override // android.app.Activity
    @InterfaceC4935d
    public void onMultiWindowModeChanged(boolean z) {
        if (this.dispatchingOnMultiWindowModeChanged) {
            return;
        }
        Iterator<androidx.core.util.a> it2 = this.onMultiWindowModeChangedListeners.iterator();
        while (it2.hasNext()) {
            it2.next().accept(new C1023j(z));
        }
    }

    @Override // android.app.Activity
    public void onNewIntent(@NotNull Intent intent) {
        Intrinsics.checkNotNullParameter(intent, "intent");
        super.onNewIntent(intent);
        Iterator<androidx.core.util.a> it2 = this.onNewIntentListeners.iterator();
        while (it2.hasNext()) {
            it2.next().accept(intent);
        }
    }

    @Override // android.app.Activity, android.view.Window.Callback
    public void onPanelClosed(int i, @NotNull Menu menu) {
        Intrinsics.checkNotNullParameter(menu, "menu");
        Iterator it2 = this.menuHostHelper.b.iterator();
        while (it2.hasNext()) {
            ((W) ((InterfaceC1058o) it2.next())).a.r(menu);
        }
        super.onPanelClosed(i, menu);
    }

    @Override // android.app.Activity
    @InterfaceC4935d
    public void onPictureInPictureModeChanged(boolean z) {
        if (this.dispatchingOnPictureInPictureModeChanged) {
            return;
        }
        Iterator<androidx.core.util.a> it2 = this.onPictureInPictureModeChangedListeners.iterator();
        while (it2.hasNext()) {
            it2.next().accept(new S(z));
        }
    }

    @Override // android.app.Activity, android.view.Window.Callback
    public boolean onPreparePanel(int i, View view, @NotNull Menu menu) {
        Intrinsics.checkNotNullParameter(menu, "menu");
        if (i != 0) {
            return true;
        }
        super.onPreparePanel(i, view, menu);
        Iterator it2 = this.menuHostHelper.b.iterator();
        while (it2.hasNext()) {
            ((W) ((InterfaceC1058o) it2.next())).a.u(menu);
        }
        return true;
    }

    @Override // android.app.Activity
    public void onRequestPermissionsResult(int i, String[] permissions, int[] grantResults) {
        Intrinsics.checkNotNullParameter(permissions, "permissions");
        Intrinsics.checkNotNullParameter(grantResults, "grantResults");
        if (this.activityResultRegistry.a(i, -1, new Intent().putExtra("androidx.activity.result.contract.extra.PERMISSIONS", permissions).putExtra("androidx.activity.result.contract.extra.PERMISSION_GRANT_RESULTS", grantResults))) {
            return;
        }
        super.onRequestPermissionsResult(i, permissions, grantResults);
    }

    @InterfaceC4935d
    public Object onRetainCustomNonConfigurationInstance() {
        return null;
    }

    @Override // android.app.Activity
    public final Object onRetainNonConfigurationInstance() {
        C0039k c0039k;
        Object objOnRetainCustomNonConfigurationInstance = onRetainCustomNonConfigurationInstance();
        B0 b0 = this._viewModelStore;
        if (b0 == null && (c0039k = (C0039k) getLastNonConfigurationInstance()) != null) {
            b0 = c0039k.b;
        }
        if (b0 == null && objOnRetainCustomNonConfigurationInstance == null) {
            return null;
        }
        C0039k c0039k2 = new C0039k();
        c0039k2.a = objOnRetainCustomNonConfigurationInstance;
        c0039k2.b = b0;
        return c0039k2;
    }

    @Override // androidx.core.app.AbstractActivityC1021h, android.app.Activity
    public void onSaveInstanceState(@NotNull Bundle outState) {
        Intrinsics.checkNotNullParameter(outState, "outState");
        if (getLifecycle() instanceof androidx.lifecycle.L) {
            androidx.lifecycle.C lifecycle = getLifecycle();
            Intrinsics.e(lifecycle, "null cannot be cast to non-null type androidx.lifecycle.LifecycleRegistry");
            ((androidx.lifecycle.L) lifecycle).g(androidx.lifecycle.B.c);
        }
        super.onSaveInstanceState(outState);
        this.savedStateRegistryController.b(outState);
    }

    @Override // android.app.Activity, android.content.ComponentCallbacks2
    public void onTrimMemory(int i) {
        super.onTrimMemory(i);
        Iterator<androidx.core.util.a> it2 = this.onTrimMemoryListeners.iterator();
        while (it2.hasNext()) {
            it2.next().accept(Integer.valueOf(i));
        }
    }

    @Override // android.app.Activity
    public void onUserLeaveHint() {
        super.onUserLeaveHint();
        Iterator<Runnable> it2 = this.onUserLeaveHintListeners.iterator();
        while (it2.hasNext()) {
            it2.next().run();
        }
    }

    @NotNull
    public final <I, O> androidx.activity.result.b registerForActivityResult(@NotNull androidx.activity.result.contract.a contract, @NotNull androidx.activity.result.h registry, @NotNull androidx.activity.result.a callback) {
        Intrinsics.checkNotNullParameter(contract, "contract");
        Intrinsics.checkNotNullParameter(registry, "registry");
        Intrinsics.checkNotNullParameter(callback, "callback");
        return registry.d("activity_rq#" + this.nextLocalRequestCode.getAndIncrement(), this, contract, callback);
    }

    @Override // androidx.core.view.InterfaceC1056m
    public void removeMenuProvider(@NotNull InterfaceC1058o provider) {
        Intrinsics.checkNotNullParameter(provider, "provider");
        C1057n c1057n = this.menuHostHelper;
        c1057n.b.remove(provider);
        if (c1057n.c.remove(provider) != null) {
            throw new ClassCastException();
        }
        c1057n.a.run();
    }

    @Override // androidx.core.content.f
    public final void removeOnConfigurationChangedListener(@NotNull androidx.core.util.a listener) {
        Intrinsics.checkNotNullParameter(listener, "listener");
        this.onConfigurationChangedListeners.remove(listener);
    }

    @Override // androidx.core.app.O
    public final void removeOnMultiWindowModeChangedListener(@NotNull androidx.core.util.a listener) {
        Intrinsics.checkNotNullParameter(listener, "listener");
        this.onMultiWindowModeChangedListeners.remove(listener);
    }

    @Override // androidx.core.app.P
    public final void removeOnPictureInPictureModeChangedListener(@NotNull androidx.core.util.a listener) {
        Intrinsics.checkNotNullParameter(listener, "listener");
        this.onPictureInPictureModeChangedListeners.remove(listener);
    }

    @Override // androidx.core.content.g
    public final void removeOnTrimMemoryListener(@NotNull androidx.core.util.a listener) {
        Intrinsics.checkNotNullParameter(listener, "listener");
        this.onTrimMemoryListeners.remove(listener);
    }

    @Override // android.app.Activity
    public void reportFullyDrawn() {
        try {
            if (AbstractC3359k2.d()) {
                Trace.beginSection(AbstractC3359k2.f("reportFullyDrawn() for ComponentActivity"));
            }
            super.reportFullyDrawn();
            getFullyDrawnReporter().a();
            Trace.endSection();
        } catch (Throwable th) {
            Trace.endSection();
            throw th;
        }
    }

    @Override // android.app.Activity
    public void setContentView(int i) {
        initializeViewTreeOwners();
        InterfaceExecutorC0040l interfaceExecutorC0040l = this.reportFullyDrawnExecutor;
        View decorView = getWindow().getDecorView();
        Intrinsics.checkNotNullExpressionValue(decorView, "window.decorView");
        ((ViewTreeObserverOnDrawListenerC0042n) interfaceExecutorC0040l).a(decorView);
        super.setContentView(i);
    }

    @Override // android.app.Activity
    @InterfaceC4935d
    public void startActivityForResult(@NotNull Intent intent, int i) {
        Intrinsics.checkNotNullParameter(intent, "intent");
        super.startActivityForResult(intent, i);
    }

    @Override // android.app.Activity
    @InterfaceC4935d
    public void startIntentSenderForResult(@NotNull IntentSender intent, int i, Intent intent2, int i2, int i3, int i4) throws IntentSender.SendIntentException {
        Intrinsics.checkNotNullParameter(intent, "intent");
        super.startIntentSenderForResult(intent, i, intent2, i2, i3, i4);
    }

    @Override // android.app.Activity
    @InterfaceC4935d
    public void startActivityForResult(@NotNull Intent intent, int i, Bundle bundle) {
        Intrinsics.checkNotNullParameter(intent, "intent");
        super.startActivityForResult(intent, i, bundle);
    }

    @Override // android.app.Activity
    @InterfaceC4935d
    public void startIntentSenderForResult(@NotNull IntentSender intent, int i, Intent intent2, int i2, int i3, int i4, Bundle bundle) throws IntentSender.SendIntentException {
        Intrinsics.checkNotNullParameter(intent, "intent");
        super.startIntentSenderForResult(intent, i, intent2, i2, i3, i4, bundle);
    }

    @NotNull
    public final <I, O> androidx.activity.result.b registerForActivityResult(@NotNull androidx.activity.result.contract.a contract, @NotNull androidx.activity.result.a callback) {
        Intrinsics.checkNotNullParameter(contract, "contract");
        Intrinsics.checkNotNullParameter(callback, "callback");
        return registerForActivityResult(contract, this.activityResultRegistry, callback);
    }

    @Override // android.app.Activity
    public void onMultiWindowModeChanged(boolean z, @NotNull Configuration newConfig) {
        Intrinsics.checkNotNullParameter(newConfig, "newConfig");
        this.dispatchingOnMultiWindowModeChanged = true;
        try {
            super.onMultiWindowModeChanged(z, newConfig);
            this.dispatchingOnMultiWindowModeChanged = false;
            Iterator<androidx.core.util.a> it2 = this.onMultiWindowModeChangedListeners.iterator();
            while (it2.hasNext()) {
                androidx.core.util.a next = it2.next();
                Intrinsics.checkNotNullParameter(newConfig, "newConfig");
                next.accept(new C1023j(z));
            }
        } catch (Throwable th) {
            this.dispatchingOnMultiWindowModeChanged = false;
            throw th;
        }
    }

    @Override // android.app.Activity
    public void onPictureInPictureModeChanged(boolean z, @NotNull Configuration newConfig) {
        Intrinsics.checkNotNullParameter(newConfig, "newConfig");
        this.dispatchingOnPictureInPictureModeChanged = true;
        try {
            super.onPictureInPictureModeChanged(z, newConfig);
            this.dispatchingOnPictureInPictureModeChanged = false;
            Iterator<androidx.core.util.a> it2 = this.onPictureInPictureModeChangedListeners.iterator();
            while (it2.hasNext()) {
                androidx.core.util.a next = it2.next();
                Intrinsics.checkNotNullParameter(newConfig, "newConfig");
                next.accept(new S(z));
            }
        } catch (Throwable th) {
            this.dispatchingOnPictureInPictureModeChanged = false;
            throw th;
        }
    }

    @Override // android.app.Activity
    public void setContentView(View view) {
        initializeViewTreeOwners();
        InterfaceExecutorC0040l interfaceExecutorC0040l = this.reportFullyDrawnExecutor;
        View decorView = getWindow().getDecorView();
        Intrinsics.checkNotNullExpressionValue(decorView, "window.decorView");
        ((ViewTreeObserverOnDrawListenerC0042n) interfaceExecutorC0040l).a(decorView);
        super.setContentView(view);
    }

    @Override // android.app.Activity
    public void setContentView(View view, ViewGroup.LayoutParams layoutParams) {
        initializeViewTreeOwners();
        InterfaceExecutorC0040l interfaceExecutorC0040l = this.reportFullyDrawnExecutor;
        View decorView = getWindow().getDecorView();
        Intrinsics.checkNotNullExpressionValue(decorView, "window.decorView");
        ((ViewTreeObserverOnDrawListenerC0042n) interfaceExecutorC0040l).a(decorView);
        super.setContentView(view, layoutParams);
    }
}
