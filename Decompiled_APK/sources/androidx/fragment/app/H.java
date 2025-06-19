package androidx.fragment.app;

import android.view.View;
import android.view.Window;
import androidx.core.view.InterfaceC1056m;
import androidx.core.view.InterfaceC1058o;

/* loaded from: classes.dex */
public final class H extends O implements androidx.core.content.f, androidx.core.content.g, androidx.core.app.O, androidx.core.app.P, androidx.lifecycle.C0, androidx.activity.N, androidx.activity.result.i, androidx.savedstate.f, InterfaceC1144l0, InterfaceC1056m {
    public final /* synthetic */ I e;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public H(I i) {
        super(i);
        this.e = i;
    }

    @Override // androidx.fragment.app.InterfaceC1144l0
    public final void a(AbstractC1136h0 abstractC1136h0, Fragment fragment) {
        this.e.onAttachFragment(fragment);
    }

    @Override // androidx.core.view.InterfaceC1056m
    public final void addMenuProvider(InterfaceC1058o interfaceC1058o) {
        this.e.addMenuProvider(interfaceC1058o);
    }

    @Override // androidx.core.content.f
    public final void addOnConfigurationChangedListener(androidx.core.util.a aVar) {
        this.e.addOnConfigurationChangedListener(aVar);
    }

    @Override // androidx.core.app.O
    public final void addOnMultiWindowModeChangedListener(androidx.core.util.a aVar) {
        this.e.addOnMultiWindowModeChangedListener(aVar);
    }

    @Override // androidx.core.app.P
    public final void addOnPictureInPictureModeChangedListener(androidx.core.util.a aVar) {
        this.e.addOnPictureInPictureModeChangedListener(aVar);
    }

    @Override // androidx.core.content.g
    public final void addOnTrimMemoryListener(androidx.core.util.a aVar) {
        this.e.addOnTrimMemoryListener(aVar);
    }

    @Override // androidx.fragment.app.L
    public final View b(int i) {
        return this.e.findViewById(i);
    }

    @Override // androidx.fragment.app.L
    public final boolean c() {
        Window window = this.e.getWindow();
        return (window == null || window.peekDecorView() == null) ? false : true;
    }

    @Override // androidx.activity.result.i
    public final androidx.activity.result.h getActivityResultRegistry() {
        return this.e.getActivityResultRegistry();
    }

    @Override // androidx.lifecycle.J
    public final androidx.lifecycle.C getLifecycle() {
        return this.e.mFragmentLifecycleRegistry;
    }

    @Override // androidx.activity.N
    public final androidx.activity.L getOnBackPressedDispatcher() {
        return this.e.getOnBackPressedDispatcher();
    }

    @Override // androidx.savedstate.f
    public final androidx.savedstate.d getSavedStateRegistry() {
        return this.e.getSavedStateRegistry();
    }

    @Override // androidx.lifecycle.C0
    public final androidx.lifecycle.B0 getViewModelStore() {
        return this.e.getViewModelStore();
    }

    @Override // androidx.core.view.InterfaceC1056m
    public final void removeMenuProvider(InterfaceC1058o interfaceC1058o) {
        this.e.removeMenuProvider(interfaceC1058o);
    }

    @Override // androidx.core.content.f
    public final void removeOnConfigurationChangedListener(androidx.core.util.a aVar) {
        this.e.removeOnConfigurationChangedListener(aVar);
    }

    @Override // androidx.core.app.O
    public final void removeOnMultiWindowModeChangedListener(androidx.core.util.a aVar) {
        this.e.removeOnMultiWindowModeChangedListener(aVar);
    }

    @Override // androidx.core.app.P
    public final void removeOnPictureInPictureModeChangedListener(androidx.core.util.a aVar) {
        this.e.removeOnPictureInPictureModeChangedListener(aVar);
    }

    @Override // androidx.core.content.g
    public final void removeOnTrimMemoryListener(androidx.core.util.a aVar) {
        this.e.removeOnTrimMemoryListener(aVar);
    }
}
