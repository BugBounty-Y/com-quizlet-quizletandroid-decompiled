package androidx.fragment.app;

import android.content.res.Resources;
import android.os.BadParcelableException;
import android.os.Bundle;
import android.os.Parcelable;
import android.util.SparseArray;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import androidx.fragment.app.strictmode.WrongFragmentContainerViolation;
import androidx.fragment.app.strictmode.WrongNestedHierarchyViolation;
import com.amazon.device.ads.DtbDeviceDataRetriever;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.Objects;
import java.util.WeakHashMap;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class o0 {
    public final J a;
    public final q0 b;
    public final Fragment c;
    public boolean d = false;
    public int e = -1;

    public o0(J j, q0 q0Var, Fragment fragment) {
        this.a = j;
        this.b = q0Var;
        this.c = fragment;
    }

    public final void a() {
        View view;
        View view2;
        int iIndexOfChild = -1;
        Fragment fragment = this.c;
        Fragment expectedParentFragment = AbstractC1136h0.G(fragment.mContainer);
        Fragment parentFragment = fragment.getParentFragment();
        if (expectedParentFragment != null && !expectedParentFragment.equals(parentFragment)) {
            int i = fragment.mContainerId;
            androidx.fragment.app.strictmode.b bVar = androidx.fragment.app.strictmode.c.a;
            Intrinsics.checkNotNullParameter(fragment, "fragment");
            Intrinsics.checkNotNullParameter(expectedParentFragment, "expectedParentFragment");
            Intrinsics.checkNotNullParameter(fragment, "fragment");
            Intrinsics.checkNotNullParameter(expectedParentFragment, "expectedParentFragment");
            StringBuilder sb = new StringBuilder("Attempting to nest fragment ");
            sb.append(fragment);
            sb.append(" within the view of parent fragment ");
            sb.append(expectedParentFragment);
            sb.append(" via container with ID ");
            androidx.fragment.app.strictmode.c.b(new WrongNestedHierarchyViolation(fragment, android.support.v4.media.session.a.r(sb, i, " without using parent's childFragmentManager")));
            androidx.fragment.app.strictmode.c.a(fragment).a.contains(androidx.fragment.app.strictmode.a.c);
        }
        q0 q0Var = this.b;
        q0Var.getClass();
        ViewGroup viewGroup = fragment.mContainer;
        if (viewGroup != null) {
            ArrayList arrayList = q0Var.a;
            int iIndexOf = arrayList.indexOf(fragment);
            int i2 = iIndexOf - 1;
            while (true) {
                if (i2 < 0) {
                    while (true) {
                        iIndexOf++;
                        if (iIndexOf >= arrayList.size()) {
                            break;
                        }
                        Fragment fragment2 = (Fragment) arrayList.get(iIndexOf);
                        if (fragment2.mContainer == viewGroup && (view = fragment2.mView) != null) {
                            iIndexOfChild = viewGroup.indexOfChild(view);
                            break;
                        }
                    }
                } else {
                    Fragment fragment3 = (Fragment) arrayList.get(i2);
                    if (fragment3.mContainer == viewGroup && (view2 = fragment3.mView) != null) {
                        iIndexOfChild = viewGroup.indexOfChild(view2) + 1;
                        break;
                    }
                    i2--;
                }
            }
        }
        fragment.mContainer.addView(fragment.mView, iIndexOfChild);
    }

    public final void b() {
        boolean zN = AbstractC1136h0.N(3);
        Fragment fragment = this.c;
        if (zN) {
            Objects.toString(fragment);
        }
        Fragment fragment2 = fragment.mTarget;
        o0 o0Var = null;
        q0 q0Var = this.b;
        if (fragment2 != null) {
            o0 o0Var2 = (o0) q0Var.b.get(fragment2.mWho);
            if (o0Var2 == null) {
                throw new IllegalStateException("Fragment " + fragment + " declared target fragment " + fragment.mTarget + " that does not belong to this FragmentManager!");
            }
            fragment.mTargetWho = fragment.mTarget.mWho;
            fragment.mTarget = null;
            o0Var = o0Var2;
        } else {
            String str = fragment.mTargetWho;
            if (str != null && (o0Var = (o0) q0Var.b.get(str)) == null) {
                StringBuilder sb = new StringBuilder("Fragment ");
                sb.append(fragment);
                sb.append(" declared target fragment ");
                throw new IllegalStateException(android.support.v4.media.session.a.t(sb, fragment.mTargetWho, " that does not belong to this FragmentManager!"));
            }
        }
        if (o0Var != null) {
            o0Var.i();
        }
        AbstractC1136h0 abstractC1136h0 = fragment.mFragmentManager;
        fragment.mHost = abstractC1136h0.x;
        fragment.mParentFragment = abstractC1136h0.z;
        J j = this.a;
        j.g(fragment, false);
        fragment.performAttach();
        j.b(fragment, false);
    }

    public final int c() {
        Fragment fragment = this.c;
        if (fragment.mFragmentManager == null) {
            return fragment.mState;
        }
        int iMin = this.e;
        int iOrdinal = fragment.mMaxState.ordinal();
        if (iOrdinal == 1) {
            iMin = Math.min(iMin, 0);
        } else if (iOrdinal == 2) {
            iMin = Math.min(iMin, 1);
        } else if (iOrdinal == 3) {
            iMin = Math.min(iMin, 5);
        } else if (iOrdinal != 4) {
            iMin = Math.min(iMin, -1);
        }
        if (fragment.mFromLayout) {
            if (fragment.mInLayout) {
                iMin = Math.max(this.e, 2);
                View view = fragment.mView;
                if (view != null && view.getParent() == null) {
                    iMin = Math.min(iMin, 2);
                }
            } else {
                iMin = this.e < 4 ? Math.min(iMin, fragment.mState) : Math.min(iMin, 1);
            }
        }
        if (fragment.mInDynamicContainer && fragment.mContainer == null) {
            iMin = Math.min(iMin, 4);
        }
        if (!fragment.mAdded) {
            iMin = Math.min(iMin, 1);
        }
        ViewGroup viewGroup = fragment.mContainer;
        if (viewGroup != null) {
            C1147o c1147oJ = C1147o.j(viewGroup, fragment.getParentFragmentManager());
            c1147oJ.getClass();
            Intrinsics.checkNotNullParameter(this, "fragmentStateManager");
            Intrinsics.checkNotNullExpressionValue(fragment, "fragmentStateManager.fragment");
            H0 h0G = c1147oJ.g(fragment);
            I0 i0 = h0G != null ? h0G.b : null;
            H0 h0H = c1147oJ.h(fragment);
            i0 = h0H != null ? h0H.b : null;
            int i = i0 == null ? -1 : K0.a[i0.ordinal()];
            if (i != -1 && i != 1) {
                i0 = i0;
            }
        }
        if (i0 == I0.b) {
            iMin = Math.min(iMin, 6);
        } else if (i0 == I0.c) {
            iMin = Math.max(iMin, 3);
        } else if (fragment.mRemoving) {
            iMin = fragment.isInBackStack() ? Math.min(iMin, 1) : Math.min(iMin, -1);
        }
        if (fragment.mDeferStart && fragment.mState < 5) {
            iMin = Math.min(iMin, 4);
        }
        if (fragment.mTransitioning) {
            iMin = Math.max(iMin, 3);
        }
        if (AbstractC1136h0.N(2)) {
            Objects.toString(fragment);
        }
        return iMin;
    }

    public final void d() throws Resources.NotFoundException {
        String resourceName;
        Fragment fragment = this.c;
        if (fragment.mFromLayout) {
            return;
        }
        if (AbstractC1136h0.N(3)) {
            Objects.toString(fragment);
        }
        Bundle bundle = fragment.mSavedFragmentState;
        ViewGroup container = null;
        Bundle bundle2 = bundle != null ? bundle.getBundle("savedInstanceState") : null;
        LayoutInflater layoutInflaterPerformGetLayoutInflater = fragment.performGetLayoutInflater(bundle2);
        ViewGroup viewGroup = fragment.mContainer;
        if (viewGroup != null) {
            container = viewGroup;
        } else {
            int i = fragment.mContainerId;
            if (i != 0) {
                if (i == -1) {
                    throw new IllegalArgumentException(androidx.compose.ui.node.B.g("Cannot create fragment ", fragment, " for a container view with no id"));
                }
                container = (ViewGroup) fragment.mFragmentManager.y.b(i);
                if (container == null) {
                    if (!fragment.mRestored && !fragment.mInDynamicContainer) {
                        try {
                            resourceName = fragment.getResources().getResourceName(fragment.mContainerId);
                        } catch (Resources.NotFoundException unused) {
                            resourceName = DtbDeviceDataRetriever.ORIENTATION_UNKNOWN;
                        }
                        throw new IllegalArgumentException("No view found for id 0x" + Integer.toHexString(fragment.mContainerId) + " (" + resourceName + ") for fragment " + fragment);
                    }
                } else if (!(container instanceof FragmentContainerView)) {
                    androidx.fragment.app.strictmode.b bVar = androidx.fragment.app.strictmode.c.a;
                    Intrinsics.checkNotNullParameter(fragment, "fragment");
                    Intrinsics.checkNotNullParameter(container, "container");
                    androidx.fragment.app.strictmode.c.b(new WrongFragmentContainerViolation(fragment, container));
                    androidx.fragment.app.strictmode.c.a(fragment).a.contains(androidx.fragment.app.strictmode.a.g);
                }
            }
        }
        fragment.mContainer = container;
        fragment.performCreateView(layoutInflaterPerformGetLayoutInflater, container, bundle2);
        if (fragment.mView != null) {
            if (AbstractC1136h0.N(3)) {
                Objects.toString(fragment);
            }
            fragment.mView.setSaveFromParentEnabled(false);
            fragment.mView.setTag(R.id.fragment_container_view_tag, fragment);
            if (container != null) {
                a();
            }
            if (fragment.mHidden) {
                fragment.mView.setVisibility(8);
            }
            if (fragment.mView.isAttachedToWindow()) {
                View view = fragment.mView;
                WeakHashMap weakHashMap = androidx.core.view.V.a;
                androidx.core.view.J.c(view);
            } else {
                View view2 = fragment.mView;
                view2.addOnAttachStateChangeListener(new n0(view2));
            }
            fragment.performViewCreated();
            this.a.m(fragment, fragment.mView, false);
            int visibility = fragment.mView.getVisibility();
            fragment.setPostOnViewCreatedAlpha(fragment.mView.getAlpha());
            if (fragment.mContainer != null && visibility == 0) {
                View viewFindFocus = fragment.mView.findFocus();
                if (viewFindFocus != null) {
                    fragment.setFocusedView(viewFindFocus);
                    if (AbstractC1136h0.N(2)) {
                        viewFindFocus.toString();
                        Objects.toString(fragment);
                    }
                }
                fragment.mView.setAlpha(DefinitionKt.NO_Float_VALUE);
            }
        }
        fragment.mState = 2;
    }

    public final void e() {
        Fragment fragmentB;
        boolean zN = AbstractC1136h0.N(3);
        Fragment fragment = this.c;
        if (zN) {
            Objects.toString(fragment);
        }
        boolean zIsChangingConfigurations = true;
        boolean z = fragment.mRemoving && !fragment.isInBackStack();
        q0 q0Var = this.b;
        if (z && !fragment.mBeingSaved) {
            q0Var.i(null, fragment.mWho);
        }
        if (!z) {
            C1142k0 c1142k0 = q0Var.d;
            if (!((c1142k0.b.containsKey(fragment.mWho) && c1142k0.e) ? c1142k0.f : true)) {
                String str = fragment.mTargetWho;
                if (str != null && (fragmentB = q0Var.b(str)) != null && fragmentB.mRetainInstance) {
                    fragment.mTarget = fragmentB;
                }
                fragment.mState = 0;
                return;
            }
        }
        O o = fragment.mHost;
        if (o instanceof androidx.lifecycle.C0) {
            zIsChangingConfigurations = q0Var.d.f;
        } else {
            I i = o.b;
            if (i != null) {
                zIsChangingConfigurations = true ^ i.isChangingConfigurations();
            }
        }
        if ((z && !fragment.mBeingSaved) || zIsChangingConfigurations) {
            C1142k0 c1142k02 = q0Var.d;
            c1142k02.getClass();
            if (AbstractC1136h0.N(3)) {
                Objects.toString(fragment);
            }
            c1142k02.B(fragment.mWho, false);
        }
        fragment.performDestroy();
        this.a.d(fragment, false);
        Iterator it2 = q0Var.d().iterator();
        while (it2.hasNext()) {
            o0 o0Var = (o0) it2.next();
            if (o0Var != null) {
                String str2 = fragment.mWho;
                Fragment fragment2 = o0Var.c;
                if (str2.equals(fragment2.mTargetWho)) {
                    fragment2.mTarget = fragment;
                    fragment2.mTargetWho = null;
                }
            }
        }
        String str3 = fragment.mTargetWho;
        if (str3 != null) {
            fragment.mTarget = q0Var.b(str3);
        }
        q0Var.h(this);
    }

    public final void f() {
        View view;
        boolean zN = AbstractC1136h0.N(3);
        Fragment fragment = this.c;
        if (zN) {
            Objects.toString(fragment);
        }
        ViewGroup viewGroup = fragment.mContainer;
        if (viewGroup != null && (view = fragment.mView) != null) {
            viewGroup.removeView(view);
        }
        fragment.performDestroyView();
        this.a.n(fragment, false);
        fragment.mContainer = null;
        fragment.mView = null;
        fragment.mViewLifecycleOwner = null;
        fragment.mViewLifecycleOwnerLiveData.l(null);
        fragment.mInLayout = false;
    }

    public final void g() {
        boolean zN = AbstractC1136h0.N(3);
        Fragment fragment = this.c;
        if (zN) {
            Objects.toString(fragment);
        }
        fragment.performDetach();
        this.a.e(fragment, false);
        fragment.mState = -1;
        fragment.mHost = null;
        fragment.mParentFragment = null;
        fragment.mFragmentManager = null;
        if (!fragment.mRemoving || fragment.isInBackStack()) {
            C1142k0 c1142k0 = this.b.d;
            if (!((c1142k0.b.containsKey(fragment.mWho) && c1142k0.e) ? c1142k0.f : true)) {
                return;
            }
        }
        if (AbstractC1136h0.N(3)) {
            Objects.toString(fragment);
        }
        fragment.initState();
    }

    public final void h() {
        Fragment fragment = this.c;
        if (fragment.mFromLayout && fragment.mInLayout && !fragment.mPerformedCreateView) {
            if (AbstractC1136h0.N(3)) {
                Objects.toString(fragment);
            }
            Bundle bundle = fragment.mSavedFragmentState;
            Bundle bundle2 = bundle != null ? bundle.getBundle("savedInstanceState") : null;
            fragment.performCreateView(fragment.performGetLayoutInflater(bundle2), null, bundle2);
            View view = fragment.mView;
            if (view != null) {
                view.setSaveFromParentEnabled(false);
                fragment.mView.setTag(R.id.fragment_container_view_tag, fragment);
                if (fragment.mHidden) {
                    fragment.mView.setVisibility(8);
                }
                fragment.performViewCreated();
                this.a.m(fragment, fragment.mView, false);
                fragment.mState = 2;
            }
        }
    }

    /* JADX WARN: Code restructure failed: missing block: B:174:0x0198, code lost:
    
        continue;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void i() {
        /*
            Method dump skipped, instructions count: 610
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.fragment.app.o0.i():void");
    }

    public final void j(ClassLoader classLoader) {
        Fragment fragment = this.c;
        Bundle bundle = fragment.mSavedFragmentState;
        if (bundle == null) {
            return;
        }
        bundle.setClassLoader(classLoader);
        if (fragment.mSavedFragmentState.getBundle("savedInstanceState") == null) {
            fragment.mSavedFragmentState.putBundle("savedInstanceState", new Bundle());
        }
        try {
            fragment.mSavedViewState = fragment.mSavedFragmentState.getSparseParcelableArray("viewState");
            fragment.mSavedViewRegistryState = fragment.mSavedFragmentState.getBundle("viewRegistryState");
            FragmentState fragmentState = (FragmentState) fragment.mSavedFragmentState.getParcelable("state");
            if (fragmentState != null) {
                fragment.mTargetWho = fragmentState.m;
                fragment.mTargetRequestCode = fragmentState.n;
                Boolean bool = fragment.mSavedUserVisibleHint;
                if (bool != null) {
                    fragment.mUserVisibleHint = bool.booleanValue();
                    fragment.mSavedUserVisibleHint = null;
                } else {
                    fragment.mUserVisibleHint = fragmentState.o;
                }
            }
            if (fragment.mUserVisibleHint) {
                return;
            }
            fragment.mDeferStart = true;
        } catch (BadParcelableException e) {
            throw new IllegalStateException("Failed to restore view hierarchy state for fragment " + fragment, e);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:16:0x002b  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void k() {
        /*
            r4 = this;
            r0 = 3
            boolean r0 = androidx.fragment.app.AbstractC1136h0.N(r0)
            androidx.fragment.app.Fragment r1 = r4.c
            if (r0 == 0) goto Lc
            java.util.Objects.toString(r1)
        Lc:
            android.view.View r0 = r1.getFocusedView()
            if (r0 == 0) goto L40
            android.view.View r2 = r1.mView
            if (r0 != r2) goto L17
            goto L21
        L17:
            android.view.ViewParent r2 = r0.getParent()
        L1b:
            if (r2 == 0) goto L40
            android.view.View r3 = r1.mView
            if (r2 != r3) goto L3b
        L21:
            r0.requestFocus()
            r2 = 2
            boolean r2 = androidx.fragment.app.AbstractC1136h0.N(r2)
            if (r2 == 0) goto L40
            r0.toString()
            java.util.Objects.toString(r1)
            android.view.View r0 = r1.mView
            android.view.View r0 = r0.findFocus()
            java.util.Objects.toString(r0)
            goto L40
        L3b:
            android.view.ViewParent r2 = r2.getParent()
            goto L1b
        L40:
            r0 = 0
            r1.setFocusedView(r0)
            r1.performResume()
            androidx.fragment.app.J r2 = r4.a
            r3 = 0
            r2.i(r1, r3)
            androidx.fragment.app.q0 r2 = r4.b
            java.lang.String r3 = r1.mWho
            r2.i(r0, r3)
            r1.mSavedFragmentState = r0
            r1.mSavedViewState = r0
            r1.mSavedViewRegistryState = r0
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.fragment.app.o0.k():void");
    }

    public final Bundle l() {
        Bundle bundle;
        Bundle bundle2 = new Bundle();
        Fragment fragment = this.c;
        if (fragment.mState == -1 && (bundle = fragment.mSavedFragmentState) != null) {
            bundle2.putAll(bundle);
        }
        bundle2.putParcelable("state", new FragmentState(fragment));
        if (fragment.mState > -1) {
            Bundle bundle3 = new Bundle();
            fragment.performSaveInstanceState(bundle3);
            if (!bundle3.isEmpty()) {
                bundle2.putBundle("savedInstanceState", bundle3);
            }
            this.a.j(fragment, bundle3, false);
            Bundle bundle4 = new Bundle();
            fragment.mSavedStateRegistryController.b(bundle4);
            if (!bundle4.isEmpty()) {
                bundle2.putBundle("registryState", bundle4);
            }
            Bundle bundleC0 = fragment.mChildFragmentManager.c0();
            if (!bundleC0.isEmpty()) {
                bundle2.putBundle("childFragmentManager", bundleC0);
            }
            if (fragment.mView != null) {
                m();
            }
            SparseArray<Parcelable> sparseArray = fragment.mSavedViewState;
            if (sparseArray != null) {
                bundle2.putSparseParcelableArray("viewState", sparseArray);
            }
            Bundle bundle5 = fragment.mSavedViewRegistryState;
            if (bundle5 != null) {
                bundle2.putBundle("viewRegistryState", bundle5);
            }
        }
        Bundle bundle6 = fragment.mArguments;
        if (bundle6 != null) {
            bundle2.putBundle("arguments", bundle6);
        }
        return bundle2;
    }

    public final void m() {
        Fragment fragment = this.c;
        if (fragment.mView == null) {
            return;
        }
        if (AbstractC1136h0.N(2)) {
            Objects.toString(fragment);
            Objects.toString(fragment.mView);
        }
        SparseArray<Parcelable> sparseArray = new SparseArray<>();
        fragment.mView.saveHierarchyState(sparseArray);
        if (sparseArray.size() > 0) {
            fragment.mSavedViewState = sparseArray;
        }
        Bundle bundle = new Bundle();
        fragment.mViewLifecycleOwner.f.b(bundle);
        if (bundle.isEmpty()) {
            return;
        }
        fragment.mSavedViewRegistryState = bundle;
    }

    public o0(J j, q0 q0Var, ClassLoader classLoader, N n, Bundle bundle) {
        this.a = j;
        this.b = q0Var;
        FragmentState fragmentState = (FragmentState) bundle.getParcelable("state");
        Fragment fragmentA = n.a(fragmentState.a);
        fragmentA.mWho = fragmentState.b;
        fragmentA.mFromLayout = fragmentState.c;
        fragmentA.mInDynamicContainer = fragmentState.d;
        fragmentA.mRestored = true;
        fragmentA.mFragmentId = fragmentState.e;
        fragmentA.mContainerId = fragmentState.f;
        fragmentA.mTag = fragmentState.g;
        fragmentA.mRetainInstance = fragmentState.h;
        fragmentA.mRemoving = fragmentState.i;
        fragmentA.mDetached = fragmentState.j;
        fragmentA.mHidden = fragmentState.k;
        fragmentA.mMaxState = androidx.lifecycle.B.values()[fragmentState.l];
        fragmentA.mTargetWho = fragmentState.m;
        fragmentA.mTargetRequestCode = fragmentState.n;
        fragmentA.mUserVisibleHint = fragmentState.o;
        this.c = fragmentA;
        fragmentA.mSavedFragmentState = bundle;
        Bundle bundle2 = bundle.getBundle("arguments");
        if (bundle2 != null) {
            bundle2.setClassLoader(classLoader);
        }
        fragmentA.setArguments(bundle2);
        if (AbstractC1136h0.N(2)) {
            Objects.toString(fragmentA);
        }
    }

    public o0(J j, q0 q0Var, Fragment fragment, Bundle bundle) {
        this.a = j;
        this.b = q0Var;
        this.c = fragment;
        fragment.mSavedViewState = null;
        fragment.mSavedViewRegistryState = null;
        fragment.mBackStackNesting = 0;
        fragment.mInLayout = false;
        fragment.mAdded = false;
        Fragment fragment2 = fragment.mTarget;
        fragment.mTargetWho = fragment2 != null ? fragment2.mWho : null;
        fragment.mTarget = null;
        fragment.mSavedFragmentState = bundle;
        fragment.mArguments = bundle.getBundle("arguments");
    }
}
