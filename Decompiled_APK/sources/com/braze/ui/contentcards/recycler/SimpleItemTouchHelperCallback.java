package com.braze.ui.contentcards.recycler;

import androidx.recyclerview.widget.F0;
import androidx.recyclerview.widget.I;
import androidx.recyclerview.widget.RecyclerView;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes.dex */
public class SimpleItemTouchHelperCallback extends I {

    @NotNull
    private final ItemTouchHelperAdapter adapter;

    public SimpleItemTouchHelperCallback(@NotNull ItemTouchHelperAdapter adapter) {
        Intrinsics.checkNotNullParameter(adapter, "adapter");
        this.adapter = adapter;
    }

    @Override // androidx.recyclerview.widget.I
    public int getMovementFlags(@NotNull RecyclerView recyclerView, @NotNull F0 viewHolder) {
        Intrinsics.checkNotNullParameter(recyclerView, "recyclerView");
        Intrinsics.checkNotNullParameter(viewHolder, "viewHolder");
        return I.makeMovementFlags(0, this.adapter.isItemDismissable(viewHolder.getBindingAdapterPosition()) ? 16 : 0);
    }

    @Override // androidx.recyclerview.widget.I
    public boolean isItemViewSwipeEnabled() {
        return true;
    }

    @Override // androidx.recyclerview.widget.I
    public boolean isLongPressDragEnabled() {
        return false;
    }

    @Override // androidx.recyclerview.widget.I
    public boolean onMove(@NotNull RecyclerView recyclerView, @NotNull F0 viewHolder, @NotNull F0 target) {
        Intrinsics.checkNotNullParameter(recyclerView, "recyclerView");
        Intrinsics.checkNotNullParameter(viewHolder, "viewHolder");
        Intrinsics.checkNotNullParameter(target, "target");
        return false;
    }

    @Override // androidx.recyclerview.widget.I
    public void onSwiped(@NotNull F0 viewHolder, int i) {
        Intrinsics.checkNotNullParameter(viewHolder, "viewHolder");
        this.adapter.onItemDismiss(viewHolder.getBindingAdapterPosition());
    }
}
