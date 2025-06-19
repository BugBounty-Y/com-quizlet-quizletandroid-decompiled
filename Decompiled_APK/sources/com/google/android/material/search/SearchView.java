package com.google.android.material.search;

import android.animation.AnimatorSet;
import android.animation.ValueAnimator;
import android.annotation.SuppressLint;
import android.app.Activity;
import android.content.Context;
import android.content.ContextWrapper;
import android.content.res.TypedArray;
import android.graphics.Paint;
import android.graphics.Rect;
import android.graphics.drawable.Drawable;
import android.os.Build;
import android.os.Parcel;
import android.os.Parcelable;
import android.text.Editable;
import android.text.TextUtils;
import android.util.AttributeSet;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.Menu;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.ImageButton;
import android.widget.TextView;
import androidx.activity.C0030b;
import androidx.annotation.NonNull;
import androidx.appcompat.widget.ActionMenuView;
import androidx.appcompat.widget.Toolbar;
import androidx.appcompat.widget.U0;
import androidx.appcompat.widget.u1;
import androidx.coordinatorlayout.widget.CoordinatorLayout;
import androidx.core.view.D0;
import androidx.core.view.InterfaceC1062t;
import androidx.core.view.L;
import androidx.core.view.V;
import androidx.customview.view.AbsSavedState;
import com.airbnb.lottie.s;
import com.amazon.device.ads.DtbConstants;
import com.google.android.gms.internal.ads.Yh;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3179j6;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3466h4;
import com.google.android.gms.internal.mlkit_vision_common.X3;
import com.google.android.material.appbar.MaterialToolbar;
import com.google.android.material.internal.ClippableRoundedCornerLayout;
import com.google.android.material.internal.TouchObserverFrameLayout;
import com.google.android.material.internal.p;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.WeakHashMap;

/* loaded from: classes2.dex */
public class SearchView extends FrameLayout implements androidx.coordinatorlayout.widget.a, com.google.android.material.motion.b {
    public static final /* synthetic */ int D = 0;
    public boolean A;
    public h B;
    public HashMap C;
    public final View a;
    public final ClippableRoundedCornerLayout b;
    public final View c;
    public final View d;
    public final FrameLayout e;
    public final FrameLayout f;
    public final MaterialToolbar g;
    public final Toolbar h;
    public final TextView i;
    public final EditText j;
    public final ImageButton k;
    public final View l;
    public final TouchObserverFrameLayout m;
    public final boolean n;
    public final Yh o;
    public final com.quizlet.data.repository.folderwithcreator.e p;
    public final boolean q;
    public final com.google.android.material.elevation.a r;
    public final LinkedHashSet s;
    public SearchBar t;
    public int u;
    public boolean v;
    public boolean w;
    public boolean x;
    public final int y;
    public boolean z;

    public static class Behavior extends androidx.coordinatorlayout.widget.b {
        public Behavior() {
        }

        @Override // androidx.coordinatorlayout.widget.b
        public final boolean h(CoordinatorLayout coordinatorLayout, View view, View view2) {
            SearchView searchView = (SearchView) view;
            if (searchView.t != null || !(view2 instanceof SearchBar)) {
                return false;
            }
            searchView.setupWithSearchBar((SearchBar) view2);
            return false;
        }

        public Behavior(@NonNull Context context, AttributeSet attributeSet) {
        }
    }

    public static class SavedState extends AbsSavedState {
        public static final Parcelable.Creator<SavedState> CREATOR = new g();
        public String c;
        public int d;

        public SavedState(Parcel parcel, ClassLoader classLoader) {
            super(parcel, classLoader);
            this.c = parcel.readString();
            this.d = parcel.readInt();
        }

        @Override // androidx.customview.view.AbsSavedState, android.os.Parcelable
        public final void writeToParcel(Parcel parcel, int i) {
            super.writeToParcel(parcel, i);
            parcel.writeString(this.c);
            parcel.writeInt(this.d);
        }
    }

    public SearchView(@NonNull Context context) {
        super(com.google.android.material.theme.overlay.a.a(context, null, R.attr.materialSearchViewStyle, R.style.Widget_Material3_SearchView), null, R.attr.materialSearchViewStyle);
        this.p = new com.quizlet.data.repository.folderwithcreator.e(this, this);
        this.s = new LinkedHashSet();
        this.u = 16;
        this.B = h.b;
        Context context2 = getContext();
        TypedArray typedArrayL = p.l(context2, null, com.google.android.material.a.J, R.attr.materialSearchViewStyle, R.style.Widget_Material3_SearchView, new int[0]);
        this.y = typedArrayL.getColor(11, 0);
        int resourceId = typedArrayL.getResourceId(16, -1);
        int resourceId2 = typedArrayL.getResourceId(0, -1);
        String string = typedArrayL.getString(3);
        String string2 = typedArrayL.getString(4);
        String string3 = typedArrayL.getString(24);
        boolean z = typedArrayL.getBoolean(27, false);
        this.v = typedArrayL.getBoolean(8, true);
        this.w = typedArrayL.getBoolean(7, true);
        boolean z2 = typedArrayL.getBoolean(17, false);
        this.x = typedArrayL.getBoolean(9, true);
        this.q = typedArrayL.getBoolean(10, true);
        typedArrayL.recycle();
        LayoutInflater.from(context2).inflate(R.layout.mtrl_search_view, this);
        this.n = true;
        this.a = findViewById(R.id.open_search_view_scrim);
        ClippableRoundedCornerLayout clippableRoundedCornerLayout = (ClippableRoundedCornerLayout) findViewById(R.id.open_search_view_root);
        this.b = clippableRoundedCornerLayout;
        this.c = findViewById(R.id.open_search_view_background);
        View viewFindViewById = findViewById(R.id.open_search_view_status_bar_spacer);
        this.d = viewFindViewById;
        this.e = (FrameLayout) findViewById(R.id.open_search_view_header_container);
        this.f = (FrameLayout) findViewById(R.id.open_search_view_toolbar_container);
        MaterialToolbar materialToolbar = (MaterialToolbar) findViewById(R.id.open_search_view_toolbar);
        this.g = materialToolbar;
        this.h = (Toolbar) findViewById(R.id.open_search_view_dummy_toolbar);
        this.i = (TextView) findViewById(R.id.open_search_view_search_prefix);
        EditText editText = (EditText) findViewById(R.id.open_search_view_edit_text);
        this.j = editText;
        ImageButton imageButton = (ImageButton) findViewById(R.id.open_search_view_clear_button);
        this.k = imageButton;
        View viewFindViewById2 = findViewById(R.id.open_search_view_divider);
        this.l = viewFindViewById2;
        TouchObserverFrameLayout touchObserverFrameLayout = (TouchObserverFrameLayout) findViewById(R.id.open_search_view_content_container);
        this.m = touchObserverFrameLayout;
        this.o = new Yh(this);
        this.r = new com.google.android.material.elevation.a(context2);
        clippableRoundedCornerLayout.setOnTouchListener(new com.braze.ui.a(2));
        setUpBackgroundViewElevationOverlay(getOverlayElevation());
        setUpHeaderLayout(resourceId);
        setSearchPrefixText(string3);
        if (resourceId2 != -1) {
            editText.setTextAppearance(resourceId2);
        }
        editText.setText(string);
        editText.setHint(string2);
        if (z2) {
            materialToolbar.setNavigationIcon((Drawable) null);
        } else {
            materialToolbar.setNavigationOnClickListener(new c(this, 2));
            if (z) {
                androidx.appcompat.graphics.drawable.a aVar = new androidx.appcompat.graphics.drawable.a(getContext());
                int iB = X3.b(R.attr.colorOnSurface, this);
                Paint paint = aVar.a;
                if (iB != paint.getColor()) {
                    paint.setColor(iB);
                    aVar.invalidateSelf();
                }
                materialToolbar.setNavigationIcon(aVar);
            }
        }
        imageButton.setOnClickListener(new c(this, 0));
        editText.addTextChangedListener(new U0(this, 1));
        touchObserverFrameLayout.setOnTouchListener(new com.amazon.aps.ads.util.adview.d(this, 2));
        p.f(materialToolbar, new f(this));
        final ViewGroup.MarginLayoutParams marginLayoutParams = (ViewGroup.MarginLayoutParams) viewFindViewById2.getLayoutParams();
        final int i = marginLayoutParams.leftMargin;
        final int i2 = marginLayoutParams.rightMargin;
        InterfaceC1062t interfaceC1062t = new InterfaceC1062t() { // from class: com.google.android.material.search.e
            @Override // androidx.core.view.InterfaceC1062t
            public final D0 w(D0 d0, View view) {
                int i3 = SearchView.D;
                int iB2 = d0.b() + i;
                ViewGroup.MarginLayoutParams marginLayoutParams2 = marginLayoutParams;
                marginLayoutParams2.leftMargin = iB2;
                marginLayoutParams2.rightMargin = d0.c() + i2;
                return d0;
            }
        };
        WeakHashMap weakHashMap = V.a;
        L.m(viewFindViewById2, interfaceC1062t);
        setUpStatusBarSpacer(getStatusBarHeight());
        L.m(viewFindViewById, new f(this));
    }

    public static /* synthetic */ void e(SearchView searchView, D0 d0) {
        int iD = d0.d();
        searchView.setUpStatusBarSpacer(iD);
        if (searchView.A) {
            return;
        }
        searchView.setStatusBarSpacerEnabledInternal(iD > 0);
    }

    private Window getActivityWindow() {
        Activity activity;
        Context context = getContext();
        while (true) {
            if (!(context instanceof ContextWrapper)) {
                activity = null;
                break;
            }
            if (context instanceof Activity) {
                activity = (Activity) context;
                break;
            }
            context = ((ContextWrapper) context).getBaseContext();
        }
        if (activity == null) {
            return null;
        }
        return activity.getWindow();
    }

    private float getOverlayElevation() {
        SearchBar searchBar = this.t;
        return searchBar != null ? searchBar.getCompatElevation() : getResources().getDimension(R.dimen.m3_searchview_elevation);
    }

    private int getStatusBarHeight() {
        int identifier = getResources().getIdentifier("status_bar_height", "dimen", DtbConstants.NATIVE_OS_NAME);
        if (identifier > 0) {
            return getResources().getDimensionPixelSize(identifier);
        }
        return 0;
    }

    private void setStatusBarSpacerEnabledInternal(boolean z) {
        this.d.setVisibility(z ? 0 : 8);
    }

    private void setUpBackgroundViewElevationOverlay(float f) {
        View view;
        com.google.android.material.elevation.a aVar = this.r;
        if (aVar == null || (view = this.c) == null) {
            return;
        }
        view.setBackgroundColor(aVar.a(f, this.y));
    }

    private void setUpHeaderLayout(int i) {
        if (i != -1) {
            LayoutInflater layoutInflaterFrom = LayoutInflater.from(getContext());
            FrameLayout frameLayout = this.e;
            frameLayout.addView(layoutInflaterFrom.inflate(i, (ViewGroup) frameLayout, false));
            frameLayout.setVisibility(0);
        }
    }

    private void setUpStatusBarSpacer(int i) {
        View view = this.d;
        if (view.getLayoutParams().height != i) {
            view.getLayoutParams().height = i;
            view.requestLayout();
        }
    }

    @Override // com.google.android.material.motion.b
    public final void a(C0030b c0030b) {
        if (h() || this.t == null) {
            return;
        }
        Yh yh = this.o;
        SearchBar searchBar = (SearchBar) yh.p;
        com.google.android.material.motion.g gVar = (com.google.android.material.motion.g) yh.n;
        gVar.f = c0030b;
        View view = gVar.b;
        gVar.j = new Rect(view.getLeft(), view.getTop(), view.getRight(), view.getBottom());
        if (searchBar != null) {
            gVar.k = p.b(view, searchBar);
        }
        gVar.i = c0030b.b;
    }

    @Override // android.view.ViewGroup
    public final void addView(View view, int i, ViewGroup.LayoutParams layoutParams) {
        if (this.n) {
            this.m.addView(view, i, layoutParams);
        } else {
            super.addView(view, i, layoutParams);
        }
    }

    @Override // com.google.android.material.motion.b
    public final void b(C0030b c0030b) {
        if (h() || this.t == null || Build.VERSION.SDK_INT < 34) {
            return;
        }
        Yh yh = this.o;
        yh.getClass();
        float f = c0030b.c;
        if (f <= DefinitionKt.NO_Float_VALUE) {
            return;
        }
        SearchBar searchBar = (SearchBar) yh.p;
        float cornerSize = searchBar.getCornerSize();
        com.google.android.material.motion.g gVar = (com.google.android.material.motion.g) yh.n;
        if (gVar.f == null) {
            Log.w("MaterialBackHelper", "Must call startBackProgress() before updateBackProgress()");
        }
        C0030b c0030b2 = gVar.f;
        gVar.f = c0030b;
        if (c0030b2 != null) {
            if (searchBar.getVisibility() != 4) {
                searchBar.setVisibility(4);
            }
            boolean z = c0030b.d == 0;
            float interpolation = gVar.a.getInterpolation(f);
            View view = gVar.b;
            float width = view.getWidth();
            float height = view.getHeight();
            if (width > DefinitionKt.NO_Float_VALUE && height > DefinitionKt.NO_Float_VALUE) {
                float fA = com.google.android.material.animation.a.a(1.0f, 0.9f, interpolation);
                float f2 = gVar.g;
                float fA2 = com.google.android.material.animation.a.a(DefinitionKt.NO_Float_VALUE, Math.max(DefinitionKt.NO_Float_VALUE, ((width - (0.9f * width)) / 2.0f) - f2), interpolation) * (z ? 1 : -1);
                float fMin = Math.min(Math.max(DefinitionKt.NO_Float_VALUE, ((height - (fA * height)) / 2.0f) - f2), gVar.h);
                float f3 = c0030b.b - gVar.i;
                float fA3 = com.google.android.material.animation.a.a(DefinitionKt.NO_Float_VALUE, fMin, Math.abs(f3) / height) * Math.signum(f3);
                view.setScaleX(fA);
                view.setScaleY(fA);
                view.setTranslationX(fA2);
                view.setTranslationY(fA3);
                if (view instanceof ClippableRoundedCornerLayout) {
                    ((ClippableRoundedCornerLayout) view).a(r12.getLeft(), r12.getTop(), r12.getRight(), r12.getBottom(), com.google.android.material.animation.a.a(gVar.c(), cornerSize, interpolation));
                }
            }
        }
        AnimatorSet animatorSet = (AnimatorSet) yh.o;
        if (animatorSet != null) {
            animatorSet.setCurrentPlayTime((long) (f * animatorSet.getDuration()));
            return;
        }
        SearchView searchView = (SearchView) yh.b;
        if (searchView.g()) {
            searchView.f();
        }
        if (searchView.v) {
            AnimatorSet animatorSet2 = new AnimatorSet();
            yh.b(animatorSet2);
            animatorSet2.setDuration(250L);
            animatorSet2.setInterpolator(com.google.android.material.internal.j.a(false, com.google.android.material.animation.a.b));
            yh.o = animatorSet2;
            animatorSet2.start();
            ((AnimatorSet) yh.o).pause();
        }
    }

    @Override // com.google.android.material.motion.b
    public final void c() {
        if (h()) {
            return;
        }
        Yh yh = this.o;
        com.google.android.material.motion.g gVar = (com.google.android.material.motion.g) yh.n;
        C0030b c0030b = gVar.f;
        gVar.f = null;
        if (Build.VERSION.SDK_INT < 34 || this.t == null || c0030b == null) {
            if (this.B.equals(h.b) || this.B.equals(h.a)) {
                return;
            }
            yh.k();
            return;
        }
        long totalDuration = yh.k().getTotalDuration();
        SearchBar searchBar = (SearchBar) yh.p;
        com.google.android.material.motion.g gVar2 = (com.google.android.material.motion.g) yh.n;
        AnimatorSet animatorSetB = gVar2.b(searchBar);
        animatorSetB.setDuration(totalDuration);
        animatorSetB.start();
        gVar2.i = DefinitionKt.NO_Float_VALUE;
        gVar2.j = null;
        gVar2.k = null;
        if (((AnimatorSet) yh.o) != null) {
            yh.c(false).start();
            ((AnimatorSet) yh.o).resume();
        }
        yh.o = null;
    }

    @Override // com.google.android.material.motion.b
    public final void d() {
        int i = 2;
        if (h() || this.t == null || Build.VERSION.SDK_INT < 34) {
            return;
        }
        Yh yh = this.o;
        SearchBar searchBar = (SearchBar) yh.p;
        com.google.android.material.motion.g gVar = (com.google.android.material.motion.g) yh.n;
        if (gVar.a() != null) {
            AnimatorSet animatorSetB = gVar.b(searchBar);
            View view = gVar.b;
            if (view instanceof ClippableRoundedCornerLayout) {
                ClippableRoundedCornerLayout clippableRoundedCornerLayout = (ClippableRoundedCornerLayout) view;
                ValueAnimator valueAnimatorOfFloat = ValueAnimator.ofFloat(clippableRoundedCornerLayout.getCornerRadius(), gVar.c());
                valueAnimatorOfFloat.addUpdateListener(new s(clippableRoundedCornerLayout, i));
                animatorSetB.playTogether(valueAnimatorOfFloat);
            }
            animatorSetB.setDuration(gVar.e);
            animatorSetB.start();
            gVar.i = DefinitionKt.NO_Float_VALUE;
            gVar.j = null;
            gVar.k = null;
        }
        AnimatorSet animatorSet = (AnimatorSet) yh.o;
        if (animatorSet != null) {
            animatorSet.reverse();
        }
        yh.o = null;
    }

    public final void f() {
        this.j.post(new d(this, 1));
    }

    public final boolean g() {
        return this.u == 48;
    }

    public com.google.android.material.motion.g getBackHelper() {
        return (com.google.android.material.motion.g) this.o.n;
    }

    @Override // androidx.coordinatorlayout.widget.a
    @NonNull
    public androidx.coordinatorlayout.widget.b getBehavior() {
        return new Behavior();
    }

    @NonNull
    public h getCurrentTransitionState() {
        return this.B;
    }

    public int getDefaultNavigationIconResource() {
        return R.drawable.ic_arrow_back_black_24;
    }

    @NonNull
    public EditText getEditText() {
        return this.j;
    }

    public CharSequence getHint() {
        return this.j.getHint();
    }

    @NonNull
    public TextView getSearchPrefix() {
        return this.i;
    }

    public CharSequence getSearchPrefixText() {
        return this.i.getText();
    }

    @SuppressLint({"KotlinPropertyAccess"})
    public int getSoftInputMode() {
        return this.u;
    }

    @NonNull
    @SuppressLint({"KotlinPropertyAccess"})
    public Editable getText() {
        return this.j.getText();
    }

    @NonNull
    public Toolbar getToolbar() {
        return this.g;
    }

    public final boolean h() {
        return this.B.equals(h.b) || this.B.equals(h.a);
    }

    public final void i() {
        if (this.x) {
            this.j.postDelayed(new d(this, 0), 100L);
        }
    }

    public final void j(h hVar, boolean z) {
        if (this.B.equals(hVar)) {
            return;
        }
        if (z) {
            if (hVar == h.d) {
                setModalForAccessibility(true);
            } else if (hVar == h.b) {
                setModalForAccessibility(false);
            }
        }
        this.B = hVar;
        Iterator it2 = new LinkedHashSet(this.s).iterator();
        if (it2.hasNext()) {
            throw android.support.v4.media.session.a.d(it2);
        }
        m(hVar);
    }

    public final void k() {
        if (this.B.equals(h.d)) {
            return;
        }
        h hVar = this.B;
        h hVar2 = h.c;
        if (hVar.equals(hVar2)) {
            return;
        }
        final Yh yh = this.o;
        SearchBar searchBar = (SearchBar) yh.p;
        SearchView searchView = (SearchView) yh.b;
        ClippableRoundedCornerLayout clippableRoundedCornerLayout = (ClippableRoundedCornerLayout) yh.d;
        if (searchBar == null) {
            if (searchView.g()) {
                searchView.postDelayed(new d(searchView, 3), 150L);
            }
            clippableRoundedCornerLayout.setVisibility(4);
            final int i = 1;
            clippableRoundedCornerLayout.post(new Runnable() { // from class: com.google.android.material.search.j
                @Override // java.lang.Runnable
                public final void run() {
                    switch (i) {
                        case 0:
                            Yh yh2 = yh;
                            AnimatorSet animatorSetD = yh2.d(true);
                            animatorSetD.addListener(new k(yh2, 0));
                            animatorSetD.start();
                            break;
                        default:
                            Yh yh3 = yh;
                            ((ClippableRoundedCornerLayout) yh3.d).setTranslationY(r1.getHeight());
                            AnimatorSet animatorSetH = yh3.h(true);
                            animatorSetH.addListener(new k(yh3, 2));
                            animatorSetH.start();
                            break;
                    }
                }
            });
            return;
        }
        if (searchView.g()) {
            searchView.i();
        }
        searchView.setTransitionState(hVar2);
        Toolbar toolbar = (Toolbar) yh.h;
        Menu menu = toolbar.getMenu();
        if (menu != null) {
            menu.clear();
        }
        if (((SearchBar) yh.p).getMenuResId() == -1 || !searchView.w) {
            toolbar.setVisibility(8);
        } else {
            toolbar.m(((SearchBar) yh.p).getMenuResId());
            ActionMenuView actionMenuViewH = p.h(toolbar);
            if (actionMenuViewH != null) {
                for (int i2 = 0; i2 < actionMenuViewH.getChildCount(); i2++) {
                    View childAt = actionMenuViewH.getChildAt(i2);
                    childAt.setClickable(false);
                    childAt.setFocusable(false);
                    childAt.setFocusableInTouchMode(false);
                }
            }
            toolbar.setVisibility(0);
        }
        CharSequence text = ((SearchBar) yh.p).getText();
        EditText editText = (EditText) yh.j;
        editText.setText(text);
        editText.setSelection(editText.getText().length());
        clippableRoundedCornerLayout.setVisibility(4);
        final int i3 = 0;
        clippableRoundedCornerLayout.post(new Runnable() { // from class: com.google.android.material.search.j
            @Override // java.lang.Runnable
            public final void run() {
                switch (i3) {
                    case 0:
                        Yh yh2 = yh;
                        AnimatorSet animatorSetD = yh2.d(true);
                        animatorSetD.addListener(new k(yh2, 0));
                        animatorSetD.start();
                        break;
                    default:
                        Yh yh3 = yh;
                        ((ClippableRoundedCornerLayout) yh3.d).setTranslationY(r1.getHeight());
                        AnimatorSet animatorSetH = yh3.h(true);
                        animatorSetH.addListener(new k(yh3, 2));
                        animatorSetH.start();
                        break;
                }
            }
        });
    }

    public final void l(ViewGroup viewGroup, boolean z) {
        for (int i = 0; i < viewGroup.getChildCount(); i++) {
            View childAt = viewGroup.getChildAt(i);
            if (childAt != this) {
                if (childAt.findViewById(this.b.getId()) != null) {
                    l((ViewGroup) childAt, z);
                } else if (z) {
                    this.C.put(childAt, Integer.valueOf(childAt.getImportantForAccessibility()));
                    WeakHashMap weakHashMap = V.a;
                    childAt.setImportantForAccessibility(4);
                } else {
                    HashMap map = this.C;
                    if (map != null && map.containsKey(childAt)) {
                        int iIntValue = ((Integer) this.C.get(childAt)).intValue();
                        WeakHashMap weakHashMap2 = V.a;
                        childAt.setImportantForAccessibility(iIntValue);
                    }
                }
            }
        }
    }

    public final void m(h hVar) {
        com.google.android.material.motion.c cVar;
        if (this.t == null || !this.q) {
            return;
        }
        boolean zEquals = hVar.equals(h.d);
        com.quizlet.data.repository.folderwithcreator.e eVar = this.p;
        if (zEquals) {
            com.google.android.material.motion.c cVar2 = (com.google.android.material.motion.c) eVar.b;
            if (cVar2 != null) {
                cVar2.b((com.google.android.material.motion.b) eVar.c, (View) eVar.d, false);
                return;
            }
            return;
        }
        if (!hVar.equals(h.b) || (cVar = (com.google.android.material.motion.c) eVar.b) == null) {
            return;
        }
        cVar.c((View) eVar.d);
    }

    public final void n() {
        ImageButton imageButtonI = p.i(this.g);
        if (imageButtonI == null) {
            return;
        }
        int i = this.b.getVisibility() == 0 ? 1 : 0;
        Drawable drawableE = AbstractC3179j6.e(imageButtonI.getDrawable());
        if (drawableE instanceof androidx.appcompat.graphics.drawable.a) {
            androidx.appcompat.graphics.drawable.a aVar = (androidx.appcompat.graphics.drawable.a) drawableE;
            float f = i;
            if (aVar.i != f) {
                aVar.i = f;
                aVar.invalidateSelf();
            }
        }
        if (drawableE instanceof com.google.android.material.internal.d) {
            ((com.google.android.material.internal.d) drawableE).a(i);
        }
    }

    @Override // android.view.ViewGroup, android.view.View
    public final void onAttachedToWindow() {
        super.onAttachedToWindow();
        AbstractC3466h4.c(this);
    }

    @Override // android.view.View
    public final void onFinishInflate() {
        super.onFinishInflate();
        Window activityWindow = getActivityWindow();
        if (activityWindow != null) {
            this.u = activityWindow.getAttributes().softInputMode;
        }
    }

    @Override // android.view.View
    public final void onRestoreInstanceState(Parcelable parcelable) {
        if (!(parcelable instanceof SavedState)) {
            super.onRestoreInstanceState(parcelable);
            return;
        }
        SavedState savedState = (SavedState) parcelable;
        super.onRestoreInstanceState(savedState.a);
        setText(savedState.c);
        setVisible(savedState.d == 0);
    }

    @Override // android.view.View
    public final Parcelable onSaveInstanceState() {
        SavedState savedState = new SavedState(super.onSaveInstanceState());
        Editable text = getText();
        savedState.c = text == null ? null : text.toString();
        savedState.d = this.b.getVisibility();
        return savedState;
    }

    public void setAnimatedNavigationIcon(boolean z) {
        this.v = z;
    }

    public void setAutoShowKeyboard(boolean z) {
        this.x = z;
    }

    @Override // android.view.View
    public void setElevation(float f) {
        super.setElevation(f);
        setUpBackgroundViewElevationOverlay(f);
    }

    public void setHint(CharSequence charSequence) {
        this.j.setHint(charSequence);
    }

    public void setMenuItemsAnimated(boolean z) {
        this.w = z;
    }

    public void setModalForAccessibility(boolean z) {
        ViewGroup viewGroup = (ViewGroup) getRootView();
        if (z) {
            this.C = new HashMap(viewGroup.getChildCount());
        }
        l(viewGroup, z);
        if (z) {
            return;
        }
        this.C = null;
    }

    public void setOnMenuItemClickListener(u1 u1Var) {
        this.g.setOnMenuItemClickListener(u1Var);
    }

    public void setSearchPrefixText(CharSequence charSequence) {
        TextView textView = this.i;
        textView.setText(charSequence);
        textView.setVisibility(TextUtils.isEmpty(charSequence) ? 8 : 0);
    }

    public void setStatusBarSpacerEnabled(boolean z) {
        this.A = true;
        setStatusBarSpacerEnabledInternal(z);
    }

    @SuppressLint({"KotlinPropertyAccess"})
    public void setText(CharSequence charSequence) {
        this.j.setText(charSequence);
    }

    public void setToolbarTouchscreenBlocksFocus(boolean z) {
        this.g.setTouchscreenBlocksFocus(z);
    }

    public void setTransitionState(@NonNull h hVar) {
        j(hVar, true);
    }

    public void setUseWindowInsetsController(boolean z) {
        this.z = z;
    }

    public void setVisible(boolean z) {
        ClippableRoundedCornerLayout clippableRoundedCornerLayout = this.b;
        boolean z2 = clippableRoundedCornerLayout.getVisibility() == 0;
        clippableRoundedCornerLayout.setVisibility(z ? 0 : 8);
        n();
        j(z ? h.d : h.b, z2 != z);
    }

    public void setupWithSearchBar(SearchBar searchBar) {
        this.t = searchBar;
        this.o.p = searchBar;
        if (searchBar != null) {
            searchBar.setOnClickListener(new c(this, 1));
            if (Build.VERSION.SDK_INT >= 34) {
                try {
                    searchBar.setHandwritingDelegatorCallback(new d(this, 2));
                    this.j.setIsHandwritingDelegate(true);
                } catch (LinkageError unused) {
                }
            }
        }
        MaterialToolbar materialToolbar = this.g;
        if (materialToolbar != null && !(AbstractC3179j6.e(materialToolbar.getNavigationIcon()) instanceof androidx.appcompat.graphics.drawable.a)) {
            int defaultNavigationIconResource = getDefaultNavigationIconResource();
            if (this.t == null) {
                materialToolbar.setNavigationIcon(defaultNavigationIconResource);
            } else {
                Drawable drawableMutate = com.facebook.appevents.g.f(getContext(), defaultNavigationIconResource).mutate();
                if (materialToolbar.getNavigationIconTint() != null) {
                    drawableMutate.setTint(materialToolbar.getNavigationIconTint().intValue());
                }
                materialToolbar.setNavigationIcon(new com.google.android.material.internal.d(this.t.getNavigationIcon(), drawableMutate));
                n();
            }
        }
        setUpBackgroundViewElevationOverlay(getOverlayElevation());
        m(getCurrentTransitionState());
    }

    public void setHint(int i) {
        this.j.setHint(i);
    }

    public void setText(int i) {
        this.j.setText(i);
    }
}
