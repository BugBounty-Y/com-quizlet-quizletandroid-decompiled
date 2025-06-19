package com.quizlet.quizletandroid.ui.usersettings.adapters;

import android.content.Context;
import android.graphics.PorterDuff;
import android.graphics.drawable.Drawable;
import android.view.LayoutInflater;
import android.view.ViewGroup;
import androidx.recyclerview.widget.AbstractC1361d0;
import androidx.recyclerview.widget.F0;
import com.quizlet.api.model.ProfileImage;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.databinding.k0;
import com.quizlet.quizletandroid.ui.common.adapter.viewholder.h;
import com.quizlet.quizletandroid.ui.usersettings.fragments.ChangeProfileImageFragment;
import java.util.ArrayList;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class c extends AbstractC1361d0 {
    public final ChangeProfileImageFragment c;
    public final ArrayList a = new ArrayList();
    public final ArrayList b = new ArrayList();
    public int d = -1;

    public c(ChangeProfileImageFragment changeProfileImageFragment) {
        this.c = changeProfileImageFragment;
    }

    public final ProfileImage d(int i) {
        if (i < 0) {
            return null;
        }
        ChangeProfileImageFragment changeProfileImageFragment = this.c;
        boolean zY = changeProfileImageFragment.Y();
        boolean z = changeProfileImageFragment.requireArguments().getBoolean("ARG_ALLOW_CUSTOM_IMAGES");
        int i2 = i - ((z ? 1 : 0) + (zY ? 1 : 0));
        ArrayList arrayList = this.a;
        if (i2 < arrayList.size()) {
            return (ProfileImage) arrayList.get(i2);
        }
        int size = i2 - arrayList.size();
        ArrayList arrayList2 = this.b;
        if (size < arrayList2.size()) {
            return (ProfileImage) arrayList2.get(size);
        }
        timber.log.c.a(new IllegalStateException(android.support.v4.media.session.a.f(i, "Index does not map to a position: ")));
        return null;
    }

    public final void f() {
        ChangeProfileImageFragment changeProfileImageFragment = this.c;
        changeProfileImageFragment.requireArguments().getString("ARG_PROFILE_IMAGE_ID");
        String string = changeProfileImageFragment.requireArguments().getString("ARG_PROFILE_IMAGE_ID");
        if (string == null) {
            string = "";
        }
        boolean z = !string.equals(d(this.d).getId());
        if (changeProfileImageFragment.i == z) {
            return;
        }
        changeProfileImageFragment.i = z;
        changeProfileImageFragment.getActivity().invalidateOptionsMenu();
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final int getItemCount() {
        ChangeProfileImageFragment changeProfileImageFragment = this.c;
        boolean zY = changeProfileImageFragment.Y();
        boolean z = changeProfileImageFragment.requireArguments().getBoolean("ARG_ALLOW_CUSTOM_IMAGES");
        return this.b.size() + this.a.size() + (z ? 1 : 0) + (zY ? 1 : 0);
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final int getItemViewType(int i) {
        ChangeProfileImageFragment changeProfileImageFragment = this.c;
        int i2 = !changeProfileImageFragment.Y() ? 1 : 0;
        if (!changeProfileImageFragment.requireArguments().getBoolean("ARG_ALLOW_CUSTOM_IMAGES")) {
            i2++;
        }
        int i3 = i + i2;
        if (i3 != 0) {
            return i3 != 1 ? 2 : 1;
        }
        return 0;
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final void onBindViewHolder(F0 f0, int i) {
        Context context = f0.itemView.getContext();
        if (f0 instanceof a) {
            Drawable item = context.getDrawable(R.drawable.ic_sys_camera);
            item.setColorFilter(com.quizlet.themes.extensions.a.a(context, R.attr.iconColorPrimary), PorterDuff.Mode.SRC_IN);
            a aVar = (a) f0;
            Intrinsics.checkNotNullParameter(item, "item");
            ((k0) aVar.e()).b.setImageDrawable(item);
            aVar.itemView.setOnClickListener(new h(aVar, 23));
            return;
        }
        if (!(f0 instanceof b)) {
            if (f0 instanceof d) {
                ((d) f0).c(d(i));
                return;
            }
            return;
        }
        Drawable item2 = context.getDrawable(R.drawable.ic_sys_image);
        item2.setColorFilter(com.quizlet.themes.extensions.a.a(context, R.attr.iconColorPrimary), PorterDuff.Mode.SRC_IN);
        b bVar = (b) f0;
        Intrinsics.checkNotNullParameter(item2, "item");
        ((k0) bVar.e()).b.setImageDrawable(item2);
        bVar.itemView.setOnClickListener(new h(bVar, 24));
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final F0 onCreateViewHolder(ViewGroup viewGroup, int i) {
        LayoutInflater layoutInflaterFrom = LayoutInflater.from(viewGroup.getContext());
        ChangeProfileImageFragment changeProfileImageFragment = this.c;
        return i == 0 ? new a(layoutInflaterFrom.inflate(R.layout.square_icon, viewGroup, false), changeProfileImageFragment) : i == 1 ? new b(layoutInflaterFrom.inflate(R.layout.square_icon, viewGroup, false), changeProfileImageFragment) : new d(layoutInflaterFrom.inflate(R.layout.profile_image, viewGroup, false), this);
    }
}
