package com.quizlet.features.infra.legacyadapter.common;

import android.content.Context;
import android.content.res.Resources;
import android.content.res.TypedArray;
import android.util.AttributeSet;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.LinearLayout;
import androidx.constraintlayout.widget.ConstraintLayout;
import com.facebook.appevents.cloudbridge.c;
import com.facebook.appevents.i;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3143f6;
import com.google.android.gms.internal.mlkit_vision_barcode.K6;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.quizlet.data.repository.widget.b;
import com.quizlet.db.data.models.persisted.DBUser;
import com.quizlet.features.infra.legacyadapter.databinding.h;
import com.quizlet.features.infra.legacyadapter.f;
import com.quizlet.features.infra.models.Creator;
import com.quizlet.partskit.widgets.QTextView;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.u;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;
import kotlin.text.x;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class UserListTitleView extends LinearLayout {
    public final h a;
    public com.quizlet.qutils.image.loading.a b;

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public UserListTitleView(@NotNull Context context) {
        this(context, null, 6);
        Intrinsics.checkNotNullParameter(context, "context");
    }

    private final void setProfileImage(String str) {
        h hVar = this.a;
        if (str == null || str.length() == 0) {
            ((ImageView) hVar.c).setImageDrawable(null);
            return;
        }
        b bVarP = ((com.quizlet.quizletandroid.ui.common.images.loading.glide.a) getImageLoader()).a(((ImageView) hVar.c).getContext()).p(str);
        bVarP.d();
        bVarP.o((ImageView) hVar.c);
    }

    private final void setUsername(String str) {
        ((QTextView) this.a.d).setText(str);
    }

    private final void setVerifiedIconVisibility(boolean z) {
        ImageView profileVerifiedIcon = (ImageView) this.a.f;
        Intrinsics.checkNotNullExpressionValue(profileVerifiedIcon, "profileVerifiedIcon");
        c.c(profileVerifiedIcon, !z);
    }

    public final void a(String str, int i, String username, boolean z) {
        Intrinsics.checkNotNullParameter(username, "username");
        setProfileImage(str);
        setUsername(username);
        h hVar = this.a;
        try {
            if (i != 0) {
                ((QTextView) hVar.b).setText(i);
            } else {
                ((QTextView) hVar.b).setText((CharSequence) null);
            }
        } catch (Resources.NotFoundException e) {
            timber.log.c.a.f(e, x.c("\n                    badgeText (" + i + ") string resource for user \\\"" + username + "\\\" was not found;\n                    available badge ids: empty (2132017778),\n                    plus and teacher\n                "), new Object[0]);
            ((QTextView) hVar.b).setText((CharSequence) null);
        }
        QTextView profileBadgeList = (QTextView) hVar.b;
        Intrinsics.checkNotNullExpressionValue(profileBadgeList, "profileBadgeList");
        CharSequence text = ((QTextView) hVar.b).getText();
        c.c(profileBadgeList, text == null || StringsKt.O(text));
        setVerifiedIconVisibility(z);
    }

    @NotNull
    public final com.quizlet.qutils.image.loading.a getImageLoader() {
        com.quizlet.qutils.image.loading.a aVar = this.b;
        if (aVar != null) {
            return aVar;
        }
        Intrinsics.m("imageLoader");
        throw null;
    }

    public final void setImageLoader(@NotNull com.quizlet.qutils.image.loading.a aVar) {
        Intrinsics.checkNotNullParameter(aVar, "<set-?>");
        this.b = aVar;
    }

    public final void setUser(@NotNull Creator creator) {
        Intrinsics.checkNotNullParameter(creator, "creator");
        if (creator.f) {
            setVisibility(8);
            return;
        }
        setVisibility(0);
        a(creator.c, creator.d, creator.b, creator.e);
    }

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public UserListTitleView(@NotNull Context context, AttributeSet attributeSet) {
        this(context, attributeSet, 4);
        Intrinsics.checkNotNullParameter(context, "context");
    }

    /* JADX WARN: Illegal instructions before constructor call */
    public UserListTitleView(Context context, AttributeSet attributeSet, int i) throws Resources.NotFoundException {
        AttributeSet attributeSet2 = (i & 2) != 0 ? null : attributeSet;
        Intrinsics.checkNotNullParameter(context, "context");
        super(context, attributeSet2, 0);
        View viewInflate = LayoutInflater.from(context).inflate(R.layout.user_list_title, (ViewGroup) this, false);
        addView(viewInflate);
        int i2 = R.id.profileBadgeList;
        QTextView profileBadgeList = (QTextView) AbstractC3375o2.c(R.id.profileBadgeList, viewInflate);
        if (profileBadgeList != null) {
            i2 = R.id.profileImageList;
            ImageView profileImageList = (ImageView) AbstractC3375o2.c(R.id.profileImageList, viewInflate);
            if (profileImageList != null) {
                i2 = R.id.profileUsernameList;
                QTextView profileUsernameList = (QTextView) AbstractC3375o2.c(R.id.profileUsernameList, viewInflate);
                if (profileUsernameList != null) {
                    i2 = R.id.profileVerifiedIcon;
                    ImageView profileVerifiedIcon = (ImageView) AbstractC3375o2.c(R.id.profileVerifiedIcon, viewInflate);
                    if (profileVerifiedIcon != null) {
                        h hVar = new h((ConstraintLayout) viewInflate, profileBadgeList, profileImageList, profileUsernameList, profileVerifiedIcon, 0);
                        Intrinsics.checkNotNullExpressionValue(hVar, "inflate(...)");
                        this.a = hVar;
                        TypedArray typedArrayObtainStyledAttributes = getContext().getTheme().obtainStyledAttributes(attributeSet2, f.a, 0, 0);
                        Intrinsics.checkNotNullExpressionValue(typedArrayObtainStyledAttributes, "obtainStyledAttributes(...)");
                        boolean z = typedArrayObtainStyledAttributes.getBoolean(1, false);
                        Integer numB = i.b(typedArrayObtainStyledAttributes, 2, R.dimen.user_list_title_image_size);
                        Integer numB2 = i.b(typedArrayObtainStyledAttributes, 3, R.style.SubHeader_S4);
                        Integer numB3 = i.b(typedArrayObtainStyledAttributes, 0, R.style.SubHeader_S2);
                        Integer numB4 = i.b(typedArrayObtainStyledAttributes, 4, R.dimen.user_list_title_verified_icon_size);
                        a aVar = new a(z, numB, numB2, numB3, numB4, null, null);
                        typedArrayObtainStyledAttributes.recycle();
                        if (z) {
                            aVar = new a(z, Integer.valueOf(numB != null ? numB.intValue() : R.dimen.user_list_title_image_size_big), Integer.valueOf(numB2 != null ? numB2.intValue() : R.style.Header_H4), Integer.valueOf(numB3 != null ? numB3.intValue() : R.style.SubHeader_S5), Integer.valueOf(numB4 != null ? numB4.intValue() : R.dimen.user_list_title_verified_icon_size_big), Integer.valueOf(R.dimen.user_list_title_username_start_margin_big), Integer.valueOf(R.dimen.user_list_title_badge_start_margin_big));
                        }
                        Integer num = aVar.b;
                        if (num != null) {
                            int iIntValue = num.intValue();
                            Intrinsics.checkNotNullExpressionValue(profileImageList, "profileImageList");
                            AbstractC3143f6.d(profileImageList, iIntValue);
                        }
                        Integer num2 = aVar.c;
                        if (num2 != null) {
                            profileUsernameList.setTextAppearance(num2.intValue());
                        }
                        Integer num3 = aVar.d;
                        if (num3 != null) {
                            profileBadgeList.setTextAppearance(num3.intValue());
                        }
                        Integer num4 = aVar.e;
                        if (num4 != null) {
                            int iIntValue2 = num4.intValue();
                            Intrinsics.checkNotNullExpressionValue(profileVerifiedIcon, "profileVerifiedIcon");
                            AbstractC3143f6.d(profileVerifiedIcon, iIntValue2);
                        }
                        Integer num5 = aVar.f;
                        if (num5 != null) {
                            int iIntValue3 = num5.intValue();
                            Intrinsics.checkNotNullExpressionValue(profileUsernameList, "profileUsernameList");
                            Intrinsics.checkNotNullParameter(profileUsernameList, "<this>");
                            int dimensionPixelSize = profileUsernameList.getContext().getResources().getDimensionPixelSize(iIntValue3);
                            ViewGroup.LayoutParams layoutParams = profileUsernameList.getLayoutParams();
                            Intrinsics.e(layoutParams, "null cannot be cast to non-null type android.view.ViewGroup.MarginLayoutParams");
                            ((ViewGroup.MarginLayoutParams) layoutParams).setMarginStart(dimensionPixelSize);
                        }
                        Integer num6 = aVar.g;
                        if (num6 != null) {
                            int iIntValue4 = num6.intValue();
                            Intrinsics.checkNotNullExpressionValue(profileBadgeList, "profileBadgeList");
                            Intrinsics.checkNotNullParameter(profileBadgeList, "<this>");
                            int dimensionPixelSize2 = profileBadgeList.getContext().getResources().getDimensionPixelSize(iIntValue4);
                            ViewGroup.LayoutParams layoutParams2 = profileBadgeList.getLayoutParams();
                            Intrinsics.e(layoutParams2, "null cannot be cast to non-null type android.view.ViewGroup.MarginLayoutParams");
                            ((ViewGroup.MarginLayoutParams) layoutParams2).setMarginStart(dimensionPixelSize2);
                            Unit unit = Unit.a;
                        }
                        if (isInEditMode()) {
                            return;
                        }
                        this.b = (com.quizlet.qutils.image.loading.a) ((u) ((com.quizlet.features.infra.legacyadapter.di.a) K6.b(com.quizlet.features.infra.legacyadapter.di.a.class, context.getApplicationContext()))).s.get();
                        return;
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(viewInflate.getResources().getResourceName(i2)));
    }

    public final void setUser(@NotNull DBUser creator) {
        String username;
        Intrinsics.checkNotNullParameter(creator, "creator");
        if (creator.getUsername() != null) {
            username = creator.getUsername();
        } else {
            timber.log.c.a.o("Null username for user with ID (" + creator.getId() + ") and DELETED (" + creator.getDeleted() + ")", new Object[0]);
            username = "";
        }
        long id = creator.getId();
        String str = username == null ? "" : username;
        String imageUrl = creator.getImageUrl();
        setUser(new Creator(creator.getCreatorBadgeText(), id, str, imageUrl == null ? "" : imageUrl, creator.getIsVerified(), creator.getDeleted()));
    }
}
