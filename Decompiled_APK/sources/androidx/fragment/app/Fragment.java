package androidx.fragment.app;

import android.animation.Animator;
import android.annotation.SuppressLint;
import android.app.Activity;
import android.app.Application;
import android.content.ComponentCallbacks;
import android.content.Context;
import android.content.ContextWrapper;
import android.content.Intent;
import android.content.res.Configuration;
import android.content.res.Resources;
import android.os.Bundle;
import android.os.Parcel;
import android.os.Parcelable;
import android.util.AttributeSet;
import android.util.SparseArray;
import android.view.ContextMenu;
import android.view.LayoutInflater;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewGroup;
import android.view.animation.Animation;
import androidx.annotation.NonNull;
import androidx.compose.ui.platform.C0978y0;
import androidx.core.app.AbstractC1016c;
import androidx.fragment.app.strictmode.GetRetainInstanceUsageViolation;
import androidx.fragment.app.strictmode.GetTargetFragmentRequestCodeUsageViolation;
import androidx.fragment.app.strictmode.GetTargetFragmentUsageViolation;
import androidx.fragment.app.strictmode.SetRetainInstanceUsageViolation;
import androidx.fragment.app.strictmode.SetTargetFragmentUsageViolation;
import androidx.fragment.app.strictmode.SetUserVisibleHintViolation;
import androidx.lifecycle.C1247h;
import androidx.lifecycle.InterfaceC1261w;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3347h2;
import com.google.android.gms.internal.mlkit_vision_camera.C1;
import java.io.FileDescriptor;
import java.io.PrintWriter;
import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import kotlin.jvm.internal.C4950i;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public class Fragment implements ComponentCallbacks, View.OnCreateContextMenuListener, androidx.lifecycle.J, androidx.lifecycle.C0, InterfaceC1261w, androidx.savedstate.f {
    static final Object USE_DEFAULT_TRANSITION = new Object();
    boolean mAdded;
    B mAnimationInfo;
    Bundle mArguments;
    int mBackStackNesting;
    boolean mBeingSaved;
    private boolean mCalled;
    ViewGroup mContainer;
    int mContainerId;
    private int mContentLayoutId;
    androidx.lifecycle.y0 mDefaultFactory;
    boolean mDeferStart;
    boolean mDetached;
    int mFragmentId;
    AbstractC1136h0 mFragmentManager;
    boolean mFromLayout;
    boolean mHasMenu;
    boolean mHidden;
    boolean mHiddenChanged;
    O mHost;
    boolean mInDynamicContainer;
    boolean mInLayout;
    boolean mIsCreated;
    LayoutInflater mLayoutInflater;
    androidx.lifecycle.L mLifecycleRegistry;
    Fragment mParentFragment;
    boolean mPerformedCreateView;
    public String mPreviousWho;
    boolean mRemoving;
    boolean mRestored;
    boolean mRetainInstance;
    boolean mRetainInstanceChangedWhileDetached;
    Bundle mSavedFragmentState;
    androidx.savedstate.e mSavedStateRegistryController;
    Boolean mSavedUserVisibleHint;
    Bundle mSavedViewRegistryState;
    SparseArray<Parcelable> mSavedViewState;
    String mTag;
    Fragment mTarget;
    int mTargetRequestCode;
    boolean mTransitioning;
    View mView;
    A0 mViewLifecycleOwner;
    int mState = -1;

    @NonNull
    String mWho = UUID.randomUUID().toString();
    String mTargetWho = null;
    private Boolean mIsPrimaryNavigationFragment = null;

    @NonNull
    AbstractC1136h0 mChildFragmentManager = new C1138i0();
    boolean mMenuVisible = true;
    boolean mUserVisibleHint = true;
    Runnable mPostponedDurationRunnable = new B0(this, 2);
    androidx.lifecycle.B mMaxState = androidx.lifecycle.B.e;
    androidx.lifecycle.Y mViewLifecycleOwnerLiveData = new androidx.lifecycle.Y();
    private final AtomicInteger mNextLocalRequestCode = new AtomicInteger();
    private final ArrayList<C> mOnPreAttachedListeners = new ArrayList<>();
    private final C mSavedStateAttachListener = new C1154w(this);

    public static class InstantiationException extends RuntimeException {
    }

    public Fragment() {
        E();
    }

    @NonNull
    @Deprecated
    public static Fragment instantiate(@NonNull Context context, @NonNull String str, Bundle bundle) {
        try {
            Fragment fragment = (Fragment) N.c(context.getClassLoader(), str).getConstructor(null).newInstance(null);
            if (bundle == null) {
                return fragment;
            }
            bundle.setClassLoader(fragment.getClass().getClassLoader());
            fragment.setArguments(bundle);
            return fragment;
        } catch (IllegalAccessException e) {
            throw new InstantiationException(android.support.v4.media.session.a.B("Unable to instantiate fragment ", str, ": make sure class name exists, is public, and has an empty constructor that is public"), e);
        } catch (java.lang.InstantiationException e2) {
            throw new InstantiationException(android.support.v4.media.session.a.B("Unable to instantiate fragment ", str, ": make sure class name exists, is public, and has an empty constructor that is public"), e2);
        } catch (NoSuchMethodException e3) {
            throw new InstantiationException(android.support.v4.media.session.a.B("Unable to instantiate fragment ", str, ": could not find Fragment constructor"), e3);
        } catch (InvocationTargetException e4) {
            throw new InstantiationException(android.support.v4.media.session.a.B("Unable to instantiate fragment ", str, ": calling Fragment constructor caused an exception"), e4);
        }
    }

    public final B B() {
        if (this.mAnimationInfo == null) {
            B b = new B();
            Object obj = USE_DEFAULT_TRANSITION;
            b.i = obj;
            b.j = obj;
            b.k = obj;
            b.l = 1.0f;
            b.m = null;
            this.mAnimationInfo = b;
        }
        return this.mAnimationInfo;
    }

    public final int C() {
        androidx.lifecycle.B b = this.mMaxState;
        return (b == androidx.lifecycle.B.b || this.mParentFragment == null) ? b.ordinal() : Math.min(b.ordinal(), this.mParentFragment.C());
    }

    public final Fragment D(boolean z) {
        String str;
        if (z) {
            androidx.fragment.app.strictmode.b bVar = androidx.fragment.app.strictmode.c.a;
            Intrinsics.checkNotNullParameter(this, "fragment");
            Intrinsics.checkNotNullParameter(this, "fragment");
            Intrinsics.checkNotNullParameter(this, "fragment");
            androidx.fragment.app.strictmode.c.b(new GetTargetFragmentUsageViolation(this, "Attempting to get target fragment from fragment " + this));
            androidx.fragment.app.strictmode.c.a(this).a.contains(androidx.fragment.app.strictmode.a.f);
        }
        Fragment fragment = this.mTarget;
        if (fragment != null) {
            return fragment;
        }
        AbstractC1136h0 abstractC1136h0 = this.mFragmentManager;
        if (abstractC1136h0 == null || (str = this.mTargetWho) == null) {
            return null;
        }
        return abstractC1136h0.c.b(str);
    }

    public final void E() {
        this.mLifecycleRegistry = new androidx.lifecycle.L(this);
        Intrinsics.checkNotNullParameter(this, "owner");
        this.mSavedStateRegistryController = new androidx.savedstate.e(new C0978y0(this, new C1247h(this, 4)));
        this.mDefaultFactory = null;
        if (this.mOnPreAttachedListeners.contains(this.mSavedStateAttachListener)) {
            return;
        }
        C c = this.mSavedStateAttachListener;
        if (this.mState >= 0) {
            c.a();
        } else {
            this.mOnPreAttachedListeners.add(c);
        }
    }

    public final C1153v F(androidx.activity.result.contract.a aVar, androidx.arch.core.util.a aVar2, androidx.activity.result.a aVar3) {
        if (this.mState > 1) {
            throw new IllegalStateException(androidx.compose.ui.node.B.g("Fragment ", this, " is attempting to registerForActivityResult after being created. Fragments must call registerForActivityResult() before they are created (i.e. initialization, onAttach(), or onCreate())."));
        }
        AtomicReference atomicReference = new AtomicReference();
        A a = new A(this, aVar2, atomicReference, aVar, aVar3);
        if (this.mState >= 0) {
            a.a();
        } else {
            this.mOnPreAttachedListeners.add(a);
        }
        return new C1153v(atomicReference);
    }

    @NonNull
    public L createFragmentContainer() {
        return new C1155x(this);
    }

    public void dump(@NonNull String str, FileDescriptor fileDescriptor, @NonNull PrintWriter printWriter, String[] strArr) {
        printWriter.print(str);
        printWriter.print("mFragmentId=#");
        printWriter.print(Integer.toHexString(this.mFragmentId));
        printWriter.print(" mContainerId=#");
        printWriter.print(Integer.toHexString(this.mContainerId));
        printWriter.print(" mTag=");
        printWriter.println(this.mTag);
        printWriter.print(str);
        printWriter.print("mState=");
        printWriter.print(this.mState);
        printWriter.print(" mWho=");
        printWriter.print(this.mWho);
        printWriter.print(" mBackStackNesting=");
        printWriter.println(this.mBackStackNesting);
        printWriter.print(str);
        printWriter.print("mAdded=");
        printWriter.print(this.mAdded);
        printWriter.print(" mRemoving=");
        printWriter.print(this.mRemoving);
        printWriter.print(" mFromLayout=");
        printWriter.print(this.mFromLayout);
        printWriter.print(" mInLayout=");
        printWriter.println(this.mInLayout);
        printWriter.print(str);
        printWriter.print("mHidden=");
        printWriter.print(this.mHidden);
        printWriter.print(" mDetached=");
        printWriter.print(this.mDetached);
        printWriter.print(" mMenuVisible=");
        printWriter.print(this.mMenuVisible);
        printWriter.print(" mHasMenu=");
        printWriter.println(this.mHasMenu);
        printWriter.print(str);
        printWriter.print("mRetainInstance=");
        printWriter.print(this.mRetainInstance);
        printWriter.print(" mUserVisibleHint=");
        printWriter.println(this.mUserVisibleHint);
        if (this.mFragmentManager != null) {
            printWriter.print(str);
            printWriter.print("mFragmentManager=");
            printWriter.println(this.mFragmentManager);
        }
        if (this.mHost != null) {
            printWriter.print(str);
            printWriter.print("mHost=");
            printWriter.println(this.mHost);
        }
        if (this.mParentFragment != null) {
            printWriter.print(str);
            printWriter.print("mParentFragment=");
            printWriter.println(this.mParentFragment);
        }
        if (this.mArguments != null) {
            printWriter.print(str);
            printWriter.print("mArguments=");
            printWriter.println(this.mArguments);
        }
        if (this.mSavedFragmentState != null) {
            printWriter.print(str);
            printWriter.print("mSavedFragmentState=");
            printWriter.println(this.mSavedFragmentState);
        }
        if (this.mSavedViewState != null) {
            printWriter.print(str);
            printWriter.print("mSavedViewState=");
            printWriter.println(this.mSavedViewState);
        }
        if (this.mSavedViewRegistryState != null) {
            printWriter.print(str);
            printWriter.print("mSavedViewRegistryState=");
            printWriter.println(this.mSavedViewRegistryState);
        }
        Fragment fragmentD = D(false);
        if (fragmentD != null) {
            printWriter.print(str);
            printWriter.print("mTarget=");
            printWriter.print(fragmentD);
            printWriter.print(" mTargetRequestCode=");
            printWriter.println(this.mTargetRequestCode);
        }
        printWriter.print(str);
        printWriter.print("mPopDirection=");
        printWriter.println(getPopDirection());
        if (getEnterAnim() != 0) {
            printWriter.print(str);
            printWriter.print("getEnterAnim=");
            printWriter.println(getEnterAnim());
        }
        if (getExitAnim() != 0) {
            printWriter.print(str);
            printWriter.print("getExitAnim=");
            printWriter.println(getExitAnim());
        }
        if (getPopEnterAnim() != 0) {
            printWriter.print(str);
            printWriter.print("getPopEnterAnim=");
            printWriter.println(getPopEnterAnim());
        }
        if (getPopExitAnim() != 0) {
            printWriter.print(str);
            printWriter.print("getPopExitAnim=");
            printWriter.println(getPopExitAnim());
        }
        if (this.mContainer != null) {
            printWriter.print(str);
            printWriter.print("mContainer=");
            printWriter.println(this.mContainer);
        }
        if (this.mView != null) {
            printWriter.print(str);
            printWriter.print("mView=");
            printWriter.println(this.mView);
        }
        if (getAnimatingAway() != null) {
            printWriter.print(str);
            printWriter.print("mAnimatingAway=");
            printWriter.println(getAnimatingAway());
        }
        if (getContext() != null) {
            new androidx.loader.app.g(this, getViewModelStore()).b(str, fileDescriptor, printWriter, strArr);
        }
        printWriter.print(str);
        printWriter.println("Child " + this.mChildFragmentManager + ":");
        this.mChildFragmentManager.w(android.support.v4.media.session.a.k(str, "  "), fileDescriptor, printWriter, strArr);
    }

    public Activity e() {
        return getActivity();
    }

    public final boolean equals(Object obj) {
        return super.equals(obj);
    }

    public Fragment findFragmentByWho(@NonNull String str) {
        return str.equals(this.mWho) ? this : this.mChildFragmentManager.c.c(str);
    }

    @NonNull
    public String generateActivityResultKey() {
        return "fragment_" + this.mWho + "_rq#" + this.mNextLocalRequestCode.getAndIncrement();
    }

    public final I getActivity() {
        O o = this.mHost;
        if (o == null) {
            return null;
        }
        return o.a;
    }

    public boolean getAllowEnterTransitionOverlap() {
        B b = this.mAnimationInfo;
        if (b == null) {
            return true;
        }
        b.getClass();
        return true;
    }

    public boolean getAllowReturnTransitionOverlap() {
        B b = this.mAnimationInfo;
        if (b == null) {
            return true;
        }
        b.getClass();
        return true;
    }

    public View getAnimatingAway() {
        B b = this.mAnimationInfo;
        if (b == null) {
            return null;
        }
        b.getClass();
        return null;
    }

    public final Bundle getArguments() {
        return this.mArguments;
    }

    @NonNull
    public final AbstractC1136h0 getChildFragmentManager() {
        if (this.mHost != null) {
            return this.mChildFragmentManager;
        }
        throw new IllegalStateException(androidx.compose.ui.node.B.g("Fragment ", this, " has not been attached yet."));
    }

    public Context getContext() {
        O o = this.mHost;
        if (o == null) {
            return null;
        }
        return o.b;
    }

    @Override // androidx.lifecycle.InterfaceC1261w
    @NonNull
    public androidx.lifecycle.viewmodel.c getDefaultViewModelCreationExtras() {
        Application application;
        Context applicationContext = requireContext().getApplicationContext();
        while (true) {
            if (!(applicationContext instanceof ContextWrapper)) {
                application = null;
                break;
            }
            if (applicationContext instanceof Application) {
                application = (Application) applicationContext;
                break;
            }
            applicationContext = ((ContextWrapper) applicationContext).getBaseContext();
        }
        if (application == null && AbstractC1136h0.N(3)) {
            Objects.toString(requireContext().getApplicationContext());
        }
        androidx.lifecycle.viewmodel.e eVar = new androidx.lifecycle.viewmodel.e(0);
        if (application != null) {
            eVar.b(androidx.lifecycle.x0.d, application);
        }
        eVar.b(androidx.lifecycle.p0.a, this);
        eVar.b(androidx.lifecycle.p0.b, this);
        if (getArguments() != null) {
            eVar.b(androidx.lifecycle.p0.c, getArguments());
        }
        return eVar;
    }

    @Override // androidx.lifecycle.InterfaceC1261w
    @NonNull
    public androidx.lifecycle.y0 getDefaultViewModelProviderFactory() {
        Application application;
        if (this.mFragmentManager == null) {
            throw new IllegalStateException("Can't access ViewModels from detached fragment");
        }
        if (this.mDefaultFactory == null) {
            Context applicationContext = requireContext().getApplicationContext();
            while (true) {
                if (!(applicationContext instanceof ContextWrapper)) {
                    application = null;
                    break;
                }
                if (applicationContext instanceof Application) {
                    application = (Application) applicationContext;
                    break;
                }
                applicationContext = ((ContextWrapper) applicationContext).getBaseContext();
            }
            if (application == null && AbstractC1136h0.N(3)) {
                Objects.toString(requireContext().getApplicationContext());
            }
            this.mDefaultFactory = new androidx.lifecycle.s0(application, this, getArguments());
        }
        return this.mDefaultFactory;
    }

    public int getEnterAnim() {
        B b = this.mAnimationInfo;
        if (b == null) {
            return 0;
        }
        return b.b;
    }

    public Object getEnterTransition() {
        B b = this.mAnimationInfo;
        if (b == null) {
            return null;
        }
        b.getClass();
        return null;
    }

    public androidx.core.app.V getEnterTransitionCallback() {
        B b = this.mAnimationInfo;
        if (b == null) {
            return null;
        }
        b.getClass();
        return null;
    }

    public int getExitAnim() {
        B b = this.mAnimationInfo;
        if (b == null) {
            return 0;
        }
        return b.c;
    }

    public Object getExitTransition() {
        B b = this.mAnimationInfo;
        if (b == null) {
            return null;
        }
        b.getClass();
        return null;
    }

    public androidx.core.app.V getExitTransitionCallback() {
        B b = this.mAnimationInfo;
        if (b == null) {
            return null;
        }
        b.getClass();
        return null;
    }

    public View getFocusedView() {
        B b = this.mAnimationInfo;
        if (b == null) {
            return null;
        }
        return b.m;
    }

    @Deprecated
    public final AbstractC1136h0 getFragmentManager() {
        return this.mFragmentManager;
    }

    public final Object getHost() {
        O o = this.mHost;
        if (o == null) {
            return null;
        }
        return ((H) o).e;
    }

    @NonNull
    public final LayoutInflater getLayoutInflater() {
        LayoutInflater layoutInflater = this.mLayoutInflater;
        return layoutInflater == null ? performGetLayoutInflater(null) : layoutInflater;
    }

    @Override // androidx.lifecycle.J
    @NonNull
    public androidx.lifecycle.C getLifecycle() {
        return this.mLifecycleRegistry;
    }

    public int getNextTransition() {
        B b = this.mAnimationInfo;
        if (b == null) {
            return 0;
        }
        return b.f;
    }

    public final Fragment getParentFragment() {
        return this.mParentFragment;
    }

    @NonNull
    public final AbstractC1136h0 getParentFragmentManager() {
        AbstractC1136h0 abstractC1136h0 = this.mFragmentManager;
        if (abstractC1136h0 != null) {
            return abstractC1136h0;
        }
        throw new IllegalStateException(androidx.compose.ui.node.B.g("Fragment ", this, " not associated with a fragment manager."));
    }

    public boolean getPopDirection() {
        B b = this.mAnimationInfo;
        if (b == null) {
            return false;
        }
        return b.a;
    }

    public int getPopEnterAnim() {
        B b = this.mAnimationInfo;
        if (b == null) {
            return 0;
        }
        return b.d;
    }

    public int getPopExitAnim() {
        B b = this.mAnimationInfo;
        if (b == null) {
            return 0;
        }
        return b.e;
    }

    public float getPostOnViewCreatedAlpha() {
        B b = this.mAnimationInfo;
        if (b == null) {
            return 1.0f;
        }
        return b.l;
    }

    public Object getReenterTransition() {
        B b = this.mAnimationInfo;
        if (b == null) {
            return null;
        }
        Object obj = b.j;
        return obj == USE_DEFAULT_TRANSITION ? getExitTransition() : obj;
    }

    @NonNull
    public final Resources getResources() {
        return requireContext().getResources();
    }

    @Deprecated
    public final boolean getRetainInstance() {
        androidx.fragment.app.strictmode.b bVar = androidx.fragment.app.strictmode.c.a;
        Intrinsics.checkNotNullParameter(this, "fragment");
        Intrinsics.checkNotNullParameter(this, "fragment");
        Intrinsics.checkNotNullParameter(this, "fragment");
        androidx.fragment.app.strictmode.c.b(new GetRetainInstanceUsageViolation(this, "Attempting to get retain instance for fragment " + this));
        androidx.fragment.app.strictmode.c.a(this).a.contains(androidx.fragment.app.strictmode.a.d);
        return this.mRetainInstance;
    }

    public Object getReturnTransition() {
        B b = this.mAnimationInfo;
        if (b == null) {
            return null;
        }
        Object obj = b.i;
        return obj == USE_DEFAULT_TRANSITION ? getEnterTransition() : obj;
    }

    @Override // androidx.savedstate.f
    @NonNull
    public final androidx.savedstate.d getSavedStateRegistry() {
        return this.mSavedStateRegistryController.b;
    }

    public Object getSharedElementEnterTransition() {
        B b = this.mAnimationInfo;
        if (b == null) {
            return null;
        }
        b.getClass();
        return null;
    }

    public Object getSharedElementReturnTransition() {
        B b = this.mAnimationInfo;
        if (b == null) {
            return null;
        }
        Object obj = b.k;
        return obj == USE_DEFAULT_TRANSITION ? getSharedElementEnterTransition() : obj;
    }

    @NonNull
    public ArrayList<String> getSharedElementSourceNames() {
        ArrayList<String> arrayList;
        B b = this.mAnimationInfo;
        return (b == null || (arrayList = b.g) == null) ? new ArrayList<>() : arrayList;
    }

    @NonNull
    public ArrayList<String> getSharedElementTargetNames() {
        ArrayList<String> arrayList;
        B b = this.mAnimationInfo;
        return (b == null || (arrayList = b.h) == null) ? new ArrayList<>() : arrayList;
    }

    @NonNull
    public final String getString(int i) {
        return getResources().getString(i);
    }

    public final String getTag() {
        return this.mTag;
    }

    @Deprecated
    public final Fragment getTargetFragment() {
        return D(true);
    }

    @Deprecated
    public final int getTargetRequestCode() {
        androidx.fragment.app.strictmode.b bVar = androidx.fragment.app.strictmode.c.a;
        Intrinsics.checkNotNullParameter(this, "fragment");
        Intrinsics.checkNotNullParameter(this, "fragment");
        Intrinsics.checkNotNullParameter(this, "fragment");
        androidx.fragment.app.strictmode.c.b(new GetTargetFragmentRequestCodeUsageViolation(this, "Attempting to get target request code from fragment " + this));
        androidx.fragment.app.strictmode.c.a(this).a.contains(androidx.fragment.app.strictmode.a.f);
        return this.mTargetRequestCode;
    }

    public View getView() {
        return this.mView;
    }

    @NonNull
    public androidx.lifecycle.J getViewLifecycleOwner() {
        A0 a0 = this.mViewLifecycleOwner;
        if (a0 != null) {
            return a0;
        }
        throw new IllegalStateException(androidx.compose.ui.node.B.g("Can't access the Fragment View's LifecycleOwner for ", this, " when getView() is null i.e., before onCreateView() or after onDestroyView()"));
    }

    @NonNull
    public androidx.lifecycle.T getViewLifecycleOwnerLiveData() {
        return this.mViewLifecycleOwnerLiveData;
    }

    @Override // androidx.lifecycle.C0
    @NonNull
    public androidx.lifecycle.B0 getViewModelStore() {
        if (this.mFragmentManager == null) {
            throw new IllegalStateException("Can't access ViewModels from detached fragment");
        }
        int iC = C();
        androidx.lifecycle.B b = androidx.lifecycle.B.a;
        if (iC == 1) {
            throw new IllegalStateException("Calling getViewModelStore() before a Fragment reaches onCreate() when using setMaxLifecycle(INITIALIZED) is not supported");
        }
        HashMap map = this.mFragmentManager.P.d;
        androidx.lifecycle.B0 b0 = (androidx.lifecycle.B0) map.get(this.mWho);
        if (b0 != null) {
            return b0;
        }
        androidx.lifecycle.B0 b02 = new androidx.lifecycle.B0();
        map.put(this.mWho, b02);
        return b02;
    }

    public final int hashCode() {
        return super.hashCode();
    }

    public void initState() {
        E();
        this.mPreviousWho = this.mWho;
        this.mWho = UUID.randomUUID().toString();
        this.mAdded = false;
        this.mRemoving = false;
        this.mFromLayout = false;
        this.mInLayout = false;
        this.mRestored = false;
        this.mBackStackNesting = 0;
        this.mFragmentManager = null;
        this.mChildFragmentManager = new C1138i0();
        this.mHost = null;
        this.mFragmentId = 0;
        this.mContainerId = 0;
        this.mTag = null;
        this.mHidden = false;
        this.mDetached = false;
    }

    public final boolean isAdded() {
        return this.mHost != null && this.mAdded;
    }

    public final boolean isHidden() {
        if (this.mHidden) {
            return true;
        }
        AbstractC1136h0 abstractC1136h0 = this.mFragmentManager;
        if (abstractC1136h0 != null) {
            Fragment fragment = this.mParentFragment;
            abstractC1136h0.getClass();
            if (fragment == null ? false : fragment.isHidden()) {
                return true;
            }
        }
        return false;
    }

    public final boolean isInBackStack() {
        return this.mBackStackNesting > 0;
    }

    public final boolean isMenuVisible() {
        if (!this.mMenuVisible) {
            return false;
        }
        if (this.mFragmentManager != null) {
            Fragment fragment = this.mParentFragment;
            if (!(fragment == null ? true : fragment.isMenuVisible())) {
                return false;
            }
        }
        return true;
    }

    public boolean isPostponed() {
        return false;
    }

    public final boolean isRemoving() {
        return this.mRemoving;
    }

    public final boolean isResumed() {
        return this.mState >= 7;
    }

    public final boolean isStateSaved() {
        AbstractC1136h0 abstractC1136h0 = this.mFragmentManager;
        if (abstractC1136h0 == null) {
            return false;
        }
        return abstractC1136h0.R();
    }

    public final boolean isVisible() {
        View view;
        return (!isAdded() || isHidden() || (view = this.mView) == null || view.getWindowToken() == null || this.mView.getVisibility() != 0) ? false : true;
    }

    public void noteStateNotSaved() {
        this.mChildFragmentManager.T();
    }

    @Deprecated
    public void onActivityCreated(Bundle bundle) {
        this.mCalled = true;
    }

    @Deprecated
    public void onActivityResult(int i, int i2, Intent intent) {
        if (AbstractC1136h0.N(2)) {
            toString();
            Objects.toString(intent);
        }
    }

    public void onAttach(@NonNull Context context) {
        this.mCalled = true;
        O o = this.mHost;
        I i = o == null ? null : o.a;
        if (i != null) {
            this.mCalled = false;
            onAttach((Activity) i);
        }
    }

    @Deprecated
    public void onAttachFragment(@NonNull Fragment fragment) {
    }

    @Override // android.content.ComponentCallbacks
    public void onConfigurationChanged(@NonNull Configuration configuration) {
        this.mCalled = true;
    }

    public boolean onContextItemSelected(@NonNull MenuItem menuItem) {
        return false;
    }

    public void onCreate(Bundle bundle) {
        this.mCalled = true;
        restoreChildFragmentState();
        AbstractC1136h0 abstractC1136h0 = this.mChildFragmentManager;
        if (abstractC1136h0.w >= 1) {
            return;
        }
        abstractC1136h0.I = false;
        abstractC1136h0.J = false;
        abstractC1136h0.P.g = false;
        abstractC1136h0.v(1);
    }

    public Animation onCreateAnimation(int i, boolean z, int i2) {
        return null;
    }

    public Animator onCreateAnimator(int i, boolean z, int i2) {
        return null;
    }

    @Override // android.view.View.OnCreateContextMenuListener
    public void onCreateContextMenu(@NonNull ContextMenu contextMenu, @NonNull View view, ContextMenu.ContextMenuInfo contextMenuInfo) {
        requireActivity().onCreateContextMenu(contextMenu, view, contextMenuInfo);
    }

    @Deprecated
    public void onCreateOptionsMenu(@NonNull Menu menu, @NonNull MenuInflater menuInflater) {
    }

    public View onCreateView(LayoutInflater layoutInflater, ViewGroup viewGroup, Bundle bundle) {
        int i = this.mContentLayoutId;
        if (i != 0) {
            return layoutInflater.inflate(i, viewGroup, false);
        }
        return null;
    }

    public void onDestroy() {
        this.mCalled = true;
    }

    @Deprecated
    public void onDestroyOptionsMenu() {
    }

    public void onDestroyView() {
        this.mCalled = true;
    }

    public void onDetach() {
        this.mCalled = true;
    }

    @NonNull
    public LayoutInflater onGetLayoutInflater(Bundle bundle) {
        return getLayoutInflater(bundle);
    }

    public void onHiddenChanged(boolean z) {
    }

    public void onInflate(@NonNull Context context, @NonNull AttributeSet attributeSet, Bundle bundle) {
        this.mCalled = true;
        O o = this.mHost;
        I i = o == null ? null : o.a;
        if (i != null) {
            this.mCalled = false;
            onInflate((Activity) i, attributeSet, bundle);
        }
    }

    @Override // android.content.ComponentCallbacks
    public void onLowMemory() {
        this.mCalled = true;
    }

    public void onMultiWindowModeChanged(boolean z) {
    }

    @Deprecated
    public boolean onOptionsItemSelected(@NonNull MenuItem menuItem) {
        return false;
    }

    @Deprecated
    public void onOptionsMenuClosed(@NonNull Menu menu) {
    }

    public void onPause() {
        this.mCalled = true;
    }

    public void onPictureInPictureModeChanged(boolean z) {
    }

    @Deprecated
    public void onPrepareOptionsMenu(@NonNull Menu menu) {
    }

    public void onPrimaryNavigationFragmentChanged(boolean z) {
    }

    @Deprecated
    public void onRequestPermissionsResult(int i, @NonNull String[] strArr, @NonNull int[] iArr) {
    }

    public void onResume() {
        this.mCalled = true;
    }

    public void onSaveInstanceState(Bundle bundle) {
    }

    public void onStart() {
        this.mCalled = true;
    }

    public void onStop() {
        this.mCalled = true;
    }

    public void onViewCreated(@NonNull View view, Bundle bundle) {
    }

    public void onViewStateRestored(Bundle bundle) {
        this.mCalled = true;
    }

    public void performActivityCreated(Bundle bundle) {
        this.mChildFragmentManager.T();
        this.mState = 3;
        this.mCalled = false;
        onActivityCreated(bundle);
        if (!this.mCalled) {
            throw new L0(androidx.compose.ui.node.B.g("Fragment ", this, " did not call through to super.onActivityCreated()"));
        }
        if (AbstractC1136h0.N(3)) {
            toString();
        }
        if (this.mView != null) {
            Bundle bundle2 = this.mSavedFragmentState;
            restoreViewState(bundle2 != null ? bundle2.getBundle("savedInstanceState") : null);
        }
        this.mSavedFragmentState = null;
        AbstractC1136h0 abstractC1136h0 = this.mChildFragmentManager;
        abstractC1136h0.I = false;
        abstractC1136h0.J = false;
        abstractC1136h0.P.g = false;
        abstractC1136h0.v(4);
    }

    public void performAttach() {
        Iterator<C> it2 = this.mOnPreAttachedListeners.iterator();
        while (it2.hasNext()) {
            it2.next().a();
        }
        this.mOnPreAttachedListeners.clear();
        this.mChildFragmentManager.c(this.mHost, createFragmentContainer(), this);
        this.mState = 0;
        this.mCalled = false;
        onAttach((Context) this.mHost.b);
        if (!this.mCalled) {
            throw new L0(androidx.compose.ui.node.B.g("Fragment ", this, " did not call through to super.onAttach()"));
        }
        AbstractC1136h0 abstractC1136h0 = this.mFragmentManager;
        Iterator it3 = abstractC1136h0.q.iterator();
        while (it3.hasNext()) {
            ((InterfaceC1144l0) it3.next()).a(abstractC1136h0, this);
        }
        AbstractC1136h0 abstractC1136h02 = this.mChildFragmentManager;
        abstractC1136h02.I = false;
        abstractC1136h02.J = false;
        abstractC1136h02.P.g = false;
        abstractC1136h02.v(0);
    }

    public void performConfigurationChanged(@NonNull Configuration configuration) {
        onConfigurationChanged(configuration);
    }

    public boolean performContextItemSelected(@NonNull MenuItem menuItem) {
        if (this.mHidden) {
            return false;
        }
        if (onContextItemSelected(menuItem)) {
            return true;
        }
        return this.mChildFragmentManager.k(menuItem);
    }

    public void performCreate(Bundle bundle) {
        this.mChildFragmentManager.T();
        this.mState = 1;
        this.mCalled = false;
        this.mLifecycleRegistry.a(new C1156y(this));
        onCreate(bundle);
        this.mIsCreated = true;
        if (!this.mCalled) {
            throw new L0(androidx.compose.ui.node.B.g("Fragment ", this, " did not call through to super.onCreate()"));
        }
        this.mLifecycleRegistry.e(androidx.lifecycle.A.ON_CREATE);
    }

    public boolean performCreateOptionsMenu(@NonNull Menu menu, @NonNull MenuInflater menuInflater) {
        boolean z = false;
        if (this.mHidden) {
            return false;
        }
        if (this.mHasMenu && this.mMenuVisible) {
            onCreateOptionsMenu(menu, menuInflater);
            z = true;
        }
        return this.mChildFragmentManager.l(menu, menuInflater) | z;
    }

    public void performCreateView(@NonNull LayoutInflater layoutInflater, ViewGroup viewGroup, Bundle bundle) {
        this.mChildFragmentManager.T();
        this.mPerformedCreateView = true;
        this.mViewLifecycleOwner = new A0(this, getViewModelStore(), new RunnableC1152u(this, 0));
        View viewOnCreateView = onCreateView(layoutInflater, viewGroup, bundle);
        this.mView = viewOnCreateView;
        if (viewOnCreateView == null) {
            if (this.mViewLifecycleOwner.e != null) {
                throw new IllegalStateException("Called getViewLifecycleOwner() but onCreateView() returned null");
            }
            this.mViewLifecycleOwner = null;
            return;
        }
        this.mViewLifecycleOwner.b();
        if (AbstractC1136h0.N(3)) {
            Objects.toString(this.mView);
            toString();
        }
        androidx.lifecycle.p0.n(this.mView, this.mViewLifecycleOwner);
        androidx.lifecycle.p0.o(this.mView, this.mViewLifecycleOwner);
        AbstractC3347h2.e(this.mView, this.mViewLifecycleOwner);
        this.mViewLifecycleOwnerLiveData.l(this.mViewLifecycleOwner);
    }

    public void performDestroy() {
        this.mChildFragmentManager.m();
        this.mLifecycleRegistry.e(androidx.lifecycle.A.ON_DESTROY);
        this.mState = 0;
        this.mCalled = false;
        this.mIsCreated = false;
        onDestroy();
        if (!this.mCalled) {
            throw new L0(androidx.compose.ui.node.B.g("Fragment ", this, " did not call through to super.onDestroy()"));
        }
    }

    public void performDestroyView() {
        this.mChildFragmentManager.v(1);
        if (this.mView != null) {
            A0 a0 = this.mViewLifecycleOwner;
            a0.b();
            if (a0.e.d.a(androidx.lifecycle.B.c)) {
                this.mViewLifecycleOwner.a(androidx.lifecycle.A.ON_DESTROY);
            }
        }
        this.mState = 1;
        this.mCalled = false;
        onDestroyView();
        if (!this.mCalled) {
            throw new L0(androidx.compose.ui.node.B.g("Fragment ", this, " did not call through to super.onDestroyView()"));
        }
        androidx.lifecycle.B0 store = getViewModelStore();
        androidx.loader.app.e factory = androidx.loader.app.f.d;
        Intrinsics.checkNotNullParameter(store, "store");
        Intrinsics.checkNotNullParameter(factory, "factory");
        androidx.lifecycle.viewmodel.a defaultCreationExtras = androidx.lifecycle.viewmodel.a.b;
        Intrinsics.checkNotNullParameter(store, "store");
        Intrinsics.checkNotNullParameter(factory, "factory");
        Intrinsics.checkNotNullParameter(defaultCreationExtras, "defaultCreationExtras");
        com.quizlet.data.repository.metering.j jVar = new com.quizlet.data.repository.metering.j(store, factory, defaultCreationExtras);
        Intrinsics.checkNotNullParameter(androidx.loader.app.f.class, "modelClass");
        Intrinsics.checkNotNullParameter(androidx.loader.app.f.class, "<this>");
        C4950i modelClass = kotlin.jvm.internal.K.a(androidx.loader.app.f.class);
        Intrinsics.checkNotNullParameter(modelClass, "modelClass");
        Intrinsics.checkNotNullParameter(modelClass, "modelClass");
        String strB = C1.b(modelClass);
        if (strB == null) {
            throw new IllegalArgumentException("Local and anonymous classes can not be ViewModels");
        }
        androidx.collection.W w = ((androidx.loader.app.f) jVar.e(modelClass, "androidx.lifecycle.ViewModelProvider.DefaultKey:".concat(strB))).b;
        int iG = w.g();
        for (int i = 0; i < iG; i++) {
            ((androidx.loader.app.c) w.h(i)).n();
        }
        this.mPerformedCreateView = false;
    }

    public void performDetach() {
        this.mState = -1;
        this.mCalled = false;
        onDetach();
        this.mLayoutInflater = null;
        if (!this.mCalled) {
            throw new L0(androidx.compose.ui.node.B.g("Fragment ", this, " did not call through to super.onDetach()"));
        }
        AbstractC1136h0 abstractC1136h0 = this.mChildFragmentManager;
        if (abstractC1136h0.K) {
            return;
        }
        abstractC1136h0.m();
        this.mChildFragmentManager = new C1138i0();
    }

    @NonNull
    public LayoutInflater performGetLayoutInflater(Bundle bundle) {
        LayoutInflater layoutInflaterOnGetLayoutInflater = onGetLayoutInflater(bundle);
        this.mLayoutInflater = layoutInflaterOnGetLayoutInflater;
        return layoutInflaterOnGetLayoutInflater;
    }

    public void performLowMemory() {
        onLowMemory();
    }

    public void performMultiWindowModeChanged(boolean z) {
        onMultiWindowModeChanged(z);
    }

    public boolean performOptionsItemSelected(@NonNull MenuItem menuItem) {
        if (this.mHidden) {
            return false;
        }
        if (this.mHasMenu && this.mMenuVisible && onOptionsItemSelected(menuItem)) {
            return true;
        }
        return this.mChildFragmentManager.q(menuItem);
    }

    public void performOptionsMenuClosed(@NonNull Menu menu) {
        if (this.mHidden) {
            return;
        }
        if (this.mHasMenu && this.mMenuVisible) {
            onOptionsMenuClosed(menu);
        }
        this.mChildFragmentManager.r(menu);
    }

    public void performPause() {
        this.mChildFragmentManager.v(5);
        if (this.mView != null) {
            this.mViewLifecycleOwner.a(androidx.lifecycle.A.ON_PAUSE);
        }
        this.mLifecycleRegistry.e(androidx.lifecycle.A.ON_PAUSE);
        this.mState = 6;
        this.mCalled = false;
        onPause();
        if (!this.mCalled) {
            throw new L0(androidx.compose.ui.node.B.g("Fragment ", this, " did not call through to super.onPause()"));
        }
    }

    public void performPictureInPictureModeChanged(boolean z) {
        onPictureInPictureModeChanged(z);
    }

    public boolean performPrepareOptionsMenu(@NonNull Menu menu) {
        boolean z = false;
        if (this.mHidden) {
            return false;
        }
        if (this.mHasMenu && this.mMenuVisible) {
            onPrepareOptionsMenu(menu);
            z = true;
        }
        return this.mChildFragmentManager.u(menu) | z;
    }

    public void performPrimaryNavigationFragmentChanged() {
        this.mFragmentManager.getClass();
        boolean zQ = AbstractC1136h0.Q(this);
        Boolean bool = this.mIsPrimaryNavigationFragment;
        if (bool == null || bool.booleanValue() != zQ) {
            this.mIsPrimaryNavigationFragment = Boolean.valueOf(zQ);
            onPrimaryNavigationFragmentChanged(zQ);
            AbstractC1136h0 abstractC1136h0 = this.mChildFragmentManager;
            abstractC1136h0.m0();
            abstractC1136h0.s(abstractC1136h0.A);
        }
    }

    public void performResume() {
        this.mChildFragmentManager.T();
        this.mChildFragmentManager.A(true);
        this.mState = 7;
        this.mCalled = false;
        onResume();
        if (!this.mCalled) {
            throw new L0(androidx.compose.ui.node.B.g("Fragment ", this, " did not call through to super.onResume()"));
        }
        androidx.lifecycle.L l = this.mLifecycleRegistry;
        androidx.lifecycle.A a = androidx.lifecycle.A.ON_RESUME;
        l.e(a);
        if (this.mView != null) {
            this.mViewLifecycleOwner.e.e(a);
        }
        AbstractC1136h0 abstractC1136h0 = this.mChildFragmentManager;
        abstractC1136h0.I = false;
        abstractC1136h0.J = false;
        abstractC1136h0.P.g = false;
        abstractC1136h0.v(7);
    }

    public void performSaveInstanceState(Bundle bundle) {
        onSaveInstanceState(bundle);
    }

    public void performStart() {
        this.mChildFragmentManager.T();
        this.mChildFragmentManager.A(true);
        this.mState = 5;
        this.mCalled = false;
        onStart();
        if (!this.mCalled) {
            throw new L0(androidx.compose.ui.node.B.g("Fragment ", this, " did not call through to super.onStart()"));
        }
        androidx.lifecycle.L l = this.mLifecycleRegistry;
        androidx.lifecycle.A a = androidx.lifecycle.A.ON_START;
        l.e(a);
        if (this.mView != null) {
            this.mViewLifecycleOwner.e.e(a);
        }
        AbstractC1136h0 abstractC1136h0 = this.mChildFragmentManager;
        abstractC1136h0.I = false;
        abstractC1136h0.J = false;
        abstractC1136h0.P.g = false;
        abstractC1136h0.v(5);
    }

    public void performStop() {
        AbstractC1136h0 abstractC1136h0 = this.mChildFragmentManager;
        abstractC1136h0.J = true;
        abstractC1136h0.P.g = true;
        abstractC1136h0.v(4);
        if (this.mView != null) {
            this.mViewLifecycleOwner.a(androidx.lifecycle.A.ON_STOP);
        }
        this.mLifecycleRegistry.e(androidx.lifecycle.A.ON_STOP);
        this.mState = 4;
        this.mCalled = false;
        onStop();
        if (!this.mCalled) {
            throw new L0(androidx.compose.ui.node.B.g("Fragment ", this, " did not call through to super.onStop()"));
        }
    }

    public void performViewCreated() {
        Bundle bundle = this.mSavedFragmentState;
        onViewCreated(this.mView, bundle != null ? bundle.getBundle("savedInstanceState") : null);
        this.mChildFragmentManager.v(2);
    }

    @NonNull
    public final <I, O> androidx.activity.result.b registerForActivityResult(@NonNull androidx.activity.result.contract.a aVar, @NonNull androidx.activity.result.a aVar2) {
        return F(aVar, new C1157z(this, 0), aVar2);
    }

    @Deprecated
    public final void requestPermissions(@NonNull String[] permissions, int i) throws Exception {
        if (this.mHost == null) {
            throw new IllegalStateException(androidx.compose.ui.node.B.g("Fragment ", this, " not attached to Activity"));
        }
        AbstractC1136h0 parentFragmentManager = getParentFragmentManager();
        if (parentFragmentManager.F != null) {
            parentFragmentManager.G.addLast(new FragmentManager$LaunchedFragmentInfo(this.mWho, i));
            parentFragmentManager.F.a(permissions);
        } else {
            parentFragmentManager.x.getClass();
            Intrinsics.checkNotNullParameter(this, "fragment");
            Intrinsics.checkNotNullParameter(permissions, "permissions");
        }
    }

    @NonNull
    public final I requireActivity() {
        I activity = getActivity();
        if (activity != null) {
            return activity;
        }
        throw new IllegalStateException(androidx.compose.ui.node.B.g("Fragment ", this, " not attached to an activity."));
    }

    @NonNull
    public final Bundle requireArguments() {
        Bundle arguments = getArguments();
        if (arguments != null) {
            return arguments;
        }
        throw new IllegalStateException(androidx.compose.ui.node.B.g("Fragment ", this, " does not have any arguments."));
    }

    @NonNull
    public final Context requireContext() {
        Context context = getContext();
        if (context != null) {
            return context;
        }
        throw new IllegalStateException(androidx.compose.ui.node.B.g("Fragment ", this, " not attached to a context."));
    }

    @NonNull
    @Deprecated
    public final AbstractC1136h0 requireFragmentManager() {
        return getParentFragmentManager();
    }

    @NonNull
    public final Fragment requireParentFragment() {
        Fragment parentFragment = getParentFragment();
        if (parentFragment != null) {
            return parentFragment;
        }
        if (getContext() == null) {
            throw new IllegalStateException(androidx.compose.ui.node.B.g("Fragment ", this, " is not attached to any Fragment or host"));
        }
        throw new IllegalStateException("Fragment " + this + " is not a child Fragment, it is directly attached to " + getContext());
    }

    @NonNull
    public final View requireView() {
        View view = getView();
        if (view != null) {
            return view;
        }
        throw new IllegalStateException(androidx.compose.ui.node.B.g("Fragment ", this, " did not return a View from onCreateView() or this was called before onCreateView()."));
    }

    public void restoreChildFragmentState() {
        Bundle bundle;
        Bundle bundle2 = this.mSavedFragmentState;
        if (bundle2 == null || (bundle = bundle2.getBundle("childFragmentManager")) == null) {
            return;
        }
        this.mChildFragmentManager.b0(bundle);
        AbstractC1136h0 abstractC1136h0 = this.mChildFragmentManager;
        abstractC1136h0.I = false;
        abstractC1136h0.J = false;
        abstractC1136h0.P.g = false;
        abstractC1136h0.v(1);
    }

    public final void restoreViewState(Bundle bundle) {
        SparseArray<Parcelable> sparseArray = this.mSavedViewState;
        if (sparseArray != null) {
            this.mView.restoreHierarchyState(sparseArray);
            this.mSavedViewState = null;
        }
        this.mCalled = false;
        onViewStateRestored(bundle);
        if (!this.mCalled) {
            throw new L0(androidx.compose.ui.node.B.g("Fragment ", this, " did not call through to super.onViewStateRestored()"));
        }
        if (this.mView != null) {
            this.mViewLifecycleOwner.a(androidx.lifecycle.A.ON_CREATE);
        }
    }

    public void setAnimations(int i, int i2, int i3, int i4) {
        if (this.mAnimationInfo == null && i == 0 && i2 == 0 && i3 == 0 && i4 == 0) {
            return;
        }
        B().b = i;
        B().c = i2;
        B().d = i3;
        B().e = i4;
    }

    public void setArguments(Bundle bundle) {
        if (this.mFragmentManager != null && isStateSaved()) {
            throw new IllegalStateException("Fragment already added and state has been saved");
        }
        this.mArguments = bundle;
    }

    public void setFocusedView(View view) {
        B().m = view;
    }

    @Deprecated
    public void setHasOptionsMenu(boolean z) {
        if (this.mHasMenu != z) {
            this.mHasMenu = z;
            if (!isAdded() || isHidden()) {
                return;
            }
            ((H) this.mHost).e.invalidateMenu();
        }
    }

    public void setInitialSavedState(SavedState savedState) {
        Bundle bundle;
        if (this.mFragmentManager != null) {
            throw new IllegalStateException("Fragment already added");
        }
        if (savedState == null || (bundle = savedState.a) == null) {
            bundle = null;
        }
        this.mSavedFragmentState = bundle;
    }

    public void setMenuVisibility(boolean z) {
        if (this.mMenuVisible != z) {
            this.mMenuVisible = z;
            if (this.mHasMenu && isAdded() && !isHidden()) {
                ((H) this.mHost).e.invalidateMenu();
            }
        }
    }

    public void setNextTransition(int i) {
        if (this.mAnimationInfo == null && i == 0) {
            return;
        }
        B();
        this.mAnimationInfo.f = i;
    }

    public void setPopDirection(boolean z) {
        if (this.mAnimationInfo == null) {
            return;
        }
        B().a = z;
    }

    public void setPostOnViewCreatedAlpha(float f) {
        B().l = f;
    }

    @Deprecated
    public void setRetainInstance(boolean z) {
        androidx.fragment.app.strictmode.b bVar = androidx.fragment.app.strictmode.c.a;
        Intrinsics.checkNotNullParameter(this, "fragment");
        Intrinsics.checkNotNullParameter(this, "fragment");
        Intrinsics.checkNotNullParameter(this, "fragment");
        androidx.fragment.app.strictmode.c.b(new SetRetainInstanceUsageViolation(this, "Attempting to set retain instance for fragment " + this));
        androidx.fragment.app.strictmode.c.a(this).a.contains(androidx.fragment.app.strictmode.a.d);
        this.mRetainInstance = z;
        AbstractC1136h0 abstractC1136h0 = this.mFragmentManager;
        if (abstractC1136h0 == null) {
            this.mRetainInstanceChangedWhileDetached = true;
        } else if (z) {
            abstractC1136h0.P.A(this);
        } else {
            abstractC1136h0.P.C(this);
        }
    }

    public void setSharedElementNames(ArrayList<String> arrayList, ArrayList<String> arrayList2) {
        B();
        B b = this.mAnimationInfo;
        b.g = arrayList;
        b.h = arrayList2;
    }

    @Deprecated
    public void setTargetFragment(Fragment targetFragment, int i) {
        if (targetFragment != null) {
            androidx.fragment.app.strictmode.b bVar = androidx.fragment.app.strictmode.c.a;
            Intrinsics.checkNotNullParameter(this, "violatingFragment");
            Intrinsics.checkNotNullParameter(targetFragment, "targetFragment");
            Intrinsics.checkNotNullParameter(this, "fragment");
            Intrinsics.checkNotNullParameter(targetFragment, "targetFragment");
            Intrinsics.checkNotNullParameter(this, "fragment");
            androidx.fragment.app.strictmode.c.b(new SetTargetFragmentUsageViolation(this, "Attempting to set target fragment " + targetFragment + " with request code " + i + " for fragment " + this));
            androidx.fragment.app.strictmode.c.a(this).a.contains(androidx.fragment.app.strictmode.a.f);
        }
        AbstractC1136h0 abstractC1136h0 = this.mFragmentManager;
        AbstractC1136h0 abstractC1136h02 = targetFragment != null ? targetFragment.mFragmentManager : null;
        if (abstractC1136h0 != null && abstractC1136h02 != null && abstractC1136h0 != abstractC1136h02) {
            throw new IllegalArgumentException(androidx.compose.ui.node.B.g("Fragment ", targetFragment, " must share the same FragmentManager to be set as a target fragment"));
        }
        for (Fragment fragmentD = targetFragment; fragmentD != null; fragmentD = fragmentD.D(false)) {
            if (fragmentD.equals(this)) {
                throw new IllegalArgumentException("Setting " + targetFragment + " as the target of " + this + " would create a target cycle");
            }
        }
        if (targetFragment == null) {
            this.mTargetWho = null;
            this.mTarget = null;
        } else if (this.mFragmentManager == null || targetFragment.mFragmentManager == null) {
            this.mTargetWho = null;
            this.mTarget = targetFragment;
        } else {
            this.mTargetWho = targetFragment.mWho;
            this.mTarget = null;
        }
        this.mTargetRequestCode = i;
    }

    @Deprecated
    public void setUserVisibleHint(boolean z) {
        androidx.fragment.app.strictmode.b bVar = androidx.fragment.app.strictmode.c.a;
        Intrinsics.checkNotNullParameter(this, "fragment");
        Intrinsics.checkNotNullParameter(this, "fragment");
        androidx.fragment.app.strictmode.c.b(new SetUserVisibleHintViolation(this, "Attempting to set user visible hint to " + z + " for fragment " + this));
        androidx.fragment.app.strictmode.c.a(this).a.contains(androidx.fragment.app.strictmode.a.e);
        boolean z2 = false;
        if (!this.mUserVisibleHint && z && this.mState < 5 && this.mFragmentManager != null && isAdded() && this.mIsCreated) {
            AbstractC1136h0 abstractC1136h0 = this.mFragmentManager;
            o0 o0VarH = abstractC1136h0.h(this);
            Fragment fragment = o0VarH.c;
            if (fragment.mDeferStart) {
                if (abstractC1136h0.b) {
                    abstractC1136h0.L = true;
                } else {
                    fragment.mDeferStart = false;
                    o0VarH.i();
                }
            }
        }
        this.mUserVisibleHint = z;
        if (this.mState < 5 && !z) {
            z2 = true;
        }
        this.mDeferStart = z2;
        if (this.mSavedFragmentState != null) {
            this.mSavedUserVisibleHint = Boolean.valueOf(z);
        }
    }

    public boolean shouldShowRequestPermissionRationale(@NonNull String str) {
        O o = this.mHost;
        if (o != null) {
            return AbstractC1016c.h(((H) o).e, str);
        }
        return false;
    }

    public void startActivity(@NonNull Intent intent) {
        startActivity(intent, null);
    }

    @Deprecated
    public void startActivityForResult(@NonNull Intent intent, int i) throws Exception {
        startActivityForResult(intent, i, null);
    }

    public void startPostponedEnterTransition() {
        if (this.mAnimationInfo != null) {
            B().getClass();
        }
    }

    @NonNull
    public String toString() {
        StringBuilder sb = new StringBuilder(128);
        sb.append(getClass().getSimpleName());
        sb.append("{");
        sb.append(Integer.toHexString(System.identityHashCode(this)));
        sb.append("} (");
        sb.append(this.mWho);
        if (this.mFragmentId != 0) {
            sb.append(" id=0x");
            sb.append(Integer.toHexString(this.mFragmentId));
        }
        if (this.mTag != null) {
            sb.append(" tag=");
            sb.append(this.mTag);
        }
        sb.append(")");
        return sb.toString();
    }

    @SuppressLint({"BanParcelableUsage, ParcelClassLoader"})
    public static class SavedState implements Parcelable {

        @NonNull
        public static final Parcelable.Creator<SavedState> CREATOR = new D();
        public final Bundle a;

        public SavedState(Bundle bundle) {
            this.a = bundle;
        }

        @Override // android.os.Parcelable
        public final int describeContents() {
            return 0;
        }

        @Override // android.os.Parcelable
        public final void writeToParcel(Parcel parcel, int i) {
            parcel.writeBundle(this.a);
        }

        public SavedState(Parcel parcel, ClassLoader classLoader) {
            Bundle bundle = parcel.readBundle();
            this.a = bundle;
            if (classLoader == null || bundle == null) {
                return;
            }
            bundle.setClassLoader(classLoader);
        }
    }

    @NonNull
    public final String getString(int i, Object... objArr) {
        return getResources().getString(i, objArr);
    }

    @NonNull
    public final <I, O> androidx.activity.result.b registerForActivityResult(@NonNull androidx.activity.result.contract.a aVar, @NonNull androidx.activity.result.h hVar, @NonNull androidx.activity.result.a aVar2) {
        return F(aVar, new C1157z(hVar, 1), aVar2);
    }

    public void startActivity(@NonNull Intent intent, Bundle bundle) {
        O o = this.mHost;
        if (o == null) {
            throw new IllegalStateException(androidx.compose.ui.node.B.g("Fragment ", this, " not attached to Activity"));
        }
        Intrinsics.checkNotNullParameter(this, "fragment");
        Intrinsics.checkNotNullParameter(intent, "intent");
        o.b.startActivity(intent, bundle);
    }

    @Deprecated
    public void startActivityForResult(@NonNull Intent intent, int i, Bundle bundle) throws Exception {
        if (this.mHost == null) {
            throw new IllegalStateException(androidx.compose.ui.node.B.g("Fragment ", this, " not attached to Activity"));
        }
        AbstractC1136h0 parentFragmentManager = getParentFragmentManager();
        if (parentFragmentManager.D != null) {
            parentFragmentManager.G.addLast(new FragmentManager$LaunchedFragmentInfo(this.mWho, i));
            if (bundle != null) {
                intent.putExtra("androidx.activity.result.contract.extra.ACTIVITY_OPTIONS_BUNDLE", bundle);
            }
            parentFragmentManager.D.a(intent);
            return;
        }
        O o = parentFragmentManager.x;
        o.getClass();
        Intrinsics.checkNotNullParameter(this, "fragment");
        Intrinsics.checkNotNullParameter(intent, "intent");
        if (i != -1) {
            throw new IllegalStateException("Starting activity with a requestCode requires a FragmentActivity host");
        }
        o.b.startActivity(intent, bundle);
    }

    @NonNull
    @Deprecated
    public LayoutInflater getLayoutInflater(Bundle bundle) {
        O o = this.mHost;
        if (o != null) {
            I i = ((H) o).e;
            LayoutInflater layoutInflaterCloneInContext = i.getLayoutInflater().cloneInContext(i);
            layoutInflaterCloneInContext.setFactory2(this.mChildFragmentManager.f);
            return layoutInflaterCloneInContext;
        }
        throw new IllegalStateException("onGetLayoutInflater() cannot be executed until the Fragment is attached to the FragmentManager.");
    }

    @Deprecated
    public void onAttach(@NonNull Activity activity) {
        this.mCalled = true;
    }

    @Deprecated
    public void onInflate(@NonNull Activity activity, @NonNull AttributeSet attributeSet, Bundle bundle) {
        this.mCalled = true;
    }
}
