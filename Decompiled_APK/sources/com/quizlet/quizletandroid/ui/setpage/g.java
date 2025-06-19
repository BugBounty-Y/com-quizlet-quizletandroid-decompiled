package com.quizlet.quizletandroid.ui.setpage;

import android.content.Intent;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.WindowManager;
import android.widget.ImageView;
import android.widget.LinearLayout;
import androidx.core.widget.NestedScrollView;
import androidx.fragment.app.Fragment;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3206m6;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.google.android.material.bottomsheet.BottomSheetBehavior;
import com.quizlet.db.data.models.base.SortOption;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.databinding.F;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes3.dex */
public final class g extends c<F> {
    public com.quizlet.db.a x;

    @Override // com.quizlet.baseui.base.BaseDaggerBottomSheetDialogFragment
    public final androidx.viewbinding.a Q(LayoutInflater inflater, ViewGroup viewGroup) {
        Intrinsics.checkNotNullParameter(inflater, "inflater");
        View viewInflate = inflater.inflate(R.layout.fragment_set_sort_bottomsheet, viewGroup, false);
        int i = R.id.alphabetical_option_icon;
        ImageView imageView = (ImageView) AbstractC3375o2.c(R.id.alphabetical_option_icon, viewInflate);
        if (imageView != null) {
            i = R.id.alphabetical_option_item;
            LinearLayout linearLayout = (LinearLayout) AbstractC3375o2.c(R.id.alphabetical_option_item, viewInflate);
            if (linearLayout != null) {
                i = R.id.original_option_icon;
                ImageView imageView2 = (ImageView) AbstractC3375o2.c(R.id.original_option_icon, viewInflate);
                if (imageView2 != null) {
                    i = R.id.original_option_item;
                    LinearLayout linearLayout2 = (LinearLayout) AbstractC3375o2.c(R.id.original_option_item, viewInflate);
                    if (linearLayout2 != null) {
                        NestedScrollView nestedScrollView = (NestedScrollView) viewInflate;
                        F f = new F(nestedScrollView, imageView, linearLayout, imageView2, linearLayout2, nestedScrollView);
                        Intrinsics.checkNotNullExpressionValue(f, "inflate(...)");
                        return f;
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(viewInflate.getResources().getResourceName(i)));
    }

    public final void U(SortOption sortOption) {
        Fragment targetFragment = getTargetFragment();
        if (targetFragment != null) {
            int targetRequestCode = getTargetRequestCode();
            Intent intent = new Intent();
            intent.putExtra("selected_sort", sortOption.getValue());
            Unit unit = Unit.a;
            targetFragment.onActivityResult(targetRequestCode, -1, intent);
        }
        G();
    }

    @Override // androidx.fragment.app.Fragment
    public final void onViewCreated(View view, Bundle bundle) {
        Intrinsics.checkNotNullParameter(view, "view");
        super.onViewCreated(view, bundle);
        androidx.viewbinding.a aVar = this.q;
        if (aVar == null) {
            throw new IllegalStateException("View binding is only valid between onCreateView and onDestroyView");
        }
        Object parent = ((F) aVar).f.getParent();
        Intrinsics.e(parent, "null cannot be cast to non-null type android.view.View");
        BottomSheetBehavior bottomSheetBehaviorC = BottomSheetBehavior.C((View) parent);
        Intrinsics.checkNotNullExpressionValue(bottomSheetBehaviorC, "from(...)");
        Object systemService = requireContext().getSystemService("window");
        Intrinsics.e(systemService, "null cannot be cast to non-null type android.view.WindowManager");
        bottomSheetBehaviorC.I(AbstractC3206m6.b((WindowManager) systemService).getHeight() / 3);
        androidx.viewbinding.a aVar2 = this.q;
        if (aVar2 == null) {
            throw new IllegalStateException("View binding is only valid between onCreateView and onDestroyView");
        }
        final F f = (F) aVar2;
        final int i = 0;
        f.e.setOnClickListener(new View.OnClickListener() { // from class: com.quizlet.quizletandroid.ui.setpage.f
            @Override // android.view.View.OnClickListener
            public final void onClick(View view2) {
                switch (i) {
                    case 0:
                        F f2 = f;
                        f2.d.setVisibility(0);
                        f2.b.setVisibility(8);
                        this.U(SortOption.ORIGINAL);
                        break;
                    default:
                        F f3 = f;
                        f3.b.setVisibility(0);
                        f3.d.setVisibility(8);
                        this.U(SortOption.ALPHABETICAL_BY_WORD);
                        break;
                }
            }
        });
        final int i2 = 1;
        f.c.setOnClickListener(new View.OnClickListener() { // from class: com.quizlet.quizletandroid.ui.setpage.f
            @Override // android.view.View.OnClickListener
            public final void onClick(View view2) {
                switch (i2) {
                    case 0:
                        F f2 = f;
                        f2.d.setVisibility(0);
                        f2.b.setVisibility(8);
                        this.U(SortOption.ORIGINAL);
                        break;
                    default:
                        F f3 = f;
                        f3.b.setVisibility(0);
                        f3.d.setVisibility(8);
                        this.U(SortOption.ALPHABETICAL_BY_WORD);
                        break;
                }
            }
        });
        long j = requireArguments().getLong("setId");
        com.quizlet.db.a aVar3 = this.x;
        if (aVar3 == null) {
            Intrinsics.m("globalSharedPreferencesManager");
            throw null;
        }
        SortOption sortOptionA = aVar3.a(j);
        Intrinsics.d(sortOptionA);
        androidx.viewbinding.a aVar4 = this.q;
        if (aVar4 == null) {
            throw new IllegalStateException("View binding is only valid between onCreateView and onDestroyView");
        }
        F f2 = (F) aVar4;
        if (sortOptionA == SortOption.ORIGINAL) {
            f2.d.setVisibility(0);
        } else {
            f2.b.setVisibility(0);
        }
    }
}
