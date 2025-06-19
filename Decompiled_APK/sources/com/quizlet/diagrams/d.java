package com.quizlet.diagrams;

import android.content.Context;
import android.view.View;
import android.widget.ImageView;
import android.widget.TextView;
import androidx.recyclerview.widget.F0;
import com.quizlet.partskit.widgets.icon.IconFontTextView;
import com.quizlet.partskit.widgets.icon.QStarIconView;
import com.quizlet.quizletandroid.R;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class d extends F0 {
    public final com.quizlet.qutils.image.loading.a a;
    public final View b;
    public final View c;
    public final TextView d;
    public final TextView e;
    public final TextView f;
    public final ImageView g;
    public final IconFontTextView h;
    public final QStarIconView i;
    public final Context j;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public d(View itemView, com.quizlet.qutils.image.loading.a imageLoader) {
        super(itemView);
        Intrinsics.checkNotNullParameter(itemView, "itemView");
        Intrinsics.checkNotNullParameter(imageLoader, "imageLoader");
        this.a = imageLoader;
        this.b = itemView.findViewById(R.id.setpage_diagram_top_border);
        this.c = itemView.findViewById(R.id.setpage_diagram_term_details_layout);
        this.d = (TextView) itemView.findViewById(R.id.setpage_diagram_term_word);
        this.e = (TextView) itemView.findViewById(R.id.setpage_diagram_term_definition);
        this.f = (TextView) itemView.findViewById(R.id.setpage_diagram_definition_label);
        this.g = (ImageView) itemView.findViewById(R.id.setpage_diagram_term_image);
        this.h = (IconFontTextView) itemView.findViewById(R.id.setpage_diagram_audio);
        this.i = (QStarIconView) itemView.findViewById(R.id.setpage_diagram_star);
        this.j = itemView.getContext();
    }
}
