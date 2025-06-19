package androidx.recyclerview.widget;

import android.os.Trace;
import android.view.ViewGroup;
import androidx.annotation.NonNull;
import java.util.List;

/* renamed from: androidx.recyclerview.widget.d0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public abstract class AbstractC1361d0 {
    private final C1363e0 mObservable = new C1363e0();
    private boolean mHasStableIds = false;
    private EnumC1359c0 mStateRestorationPolicy = EnumC1359c0.a;

    public final void bindViewHolder(@NonNull F0 f0, int i) {
        boolean z = f0.mBindingAdapter == null;
        if (z) {
            f0.mPosition = i;
            if (hasStableIds()) {
                f0.mItemId = getItemId(i);
            }
            f0.setFlags(1, 519);
            if (androidx.core.os.h.a()) {
                Trace.beginSection(String.format("RV onBindViewHolder type=0x%X", Integer.valueOf(f0.mItemViewType)));
            }
        }
        f0.mBindingAdapter = this;
        if (RecyclerView.M1) {
            if (f0.itemView.getParent() == null && f0.itemView.isAttachedToWindow() != f0.isTmpDetached()) {
                throw new IllegalStateException("Temp-detached state out of sync with reality. holder.isTmpDetached(): " + f0.isTmpDetached() + ", attached to window: " + f0.itemView.isAttachedToWindow() + ", holder: " + f0);
            }
            if (f0.itemView.getParent() == null && f0.itemView.isAttachedToWindow()) {
                throw new IllegalStateException("Attempting to bind attached holder with no parent (AKA temp detached): " + f0);
            }
        }
        onBindViewHolder(f0, i, f0.getUnmodifiedPayloads());
        if (z) {
            f0.clearPayload();
            ViewGroup.LayoutParams layoutParams = f0.itemView.getLayoutParams();
            if (layoutParams instanceof C1383o0) {
                ((C1383o0) layoutParams).c = true;
            }
            Trace.endSection();
        }
    }

    public boolean canRestoreState() {
        int iOrdinal = this.mStateRestorationPolicy.ordinal();
        if (iOrdinal != 1) {
            if (iOrdinal == 2) {
                return false;
            }
        } else if (getItemCount() <= 0) {
            return false;
        }
        return true;
    }

    @NonNull
    public final F0 createViewHolder(@NonNull ViewGroup viewGroup, int i) {
        try {
            if (androidx.core.os.h.a()) {
                Trace.beginSection(String.format("RV onCreateViewHolder type=0x%X", Integer.valueOf(i)));
            }
            F0 f0OnCreateViewHolder = onCreateViewHolder(viewGroup, i);
            if (f0OnCreateViewHolder.itemView.getParent() != null) {
                throw new IllegalStateException("ViewHolder views must not be attached when created. Ensure that you are not passing 'true' to the attachToRoot parameter of LayoutInflater.inflate(..., boolean attachToRoot)");
            }
            f0OnCreateViewHolder.mItemViewType = i;
            Trace.endSection();
            return f0OnCreateViewHolder;
        } catch (Throwable th) {
            Trace.endSection();
            throw th;
        }
    }

    public int findRelativeAdapterPositionIn(@NonNull AbstractC1361d0 abstractC1361d0, @NonNull F0 f0, int i) {
        if (abstractC1361d0 == this) {
            return i;
        }
        return -1;
    }

    public abstract int getItemCount();

    public long getItemId(int i) {
        return -1L;
    }

    public int getItemViewType(int i) {
        return 0;
    }

    @NonNull
    public final EnumC1359c0 getStateRestorationPolicy() {
        return this.mStateRestorationPolicy;
    }

    public final boolean hasObservers() {
        return this.mObservable.a();
    }

    public final boolean hasStableIds() {
        return this.mHasStableIds;
    }

    public final void notifyDataSetChanged() {
        this.mObservable.b();
    }

    public final void notifyItemChanged(int i) {
        this.mObservable.d(i, 1, null);
    }

    public final void notifyItemInserted(int i) {
        this.mObservable.e(i, 1);
    }

    public final void notifyItemMoved(int i, int i2) {
        this.mObservable.c(i, i2);
    }

    public final void notifyItemRangeChanged(int i, int i2) {
        this.mObservable.d(i, i2, null);
    }

    public final void notifyItemRangeInserted(int i, int i2) {
        this.mObservable.e(i, i2);
    }

    public final void notifyItemRangeRemoved(int i, int i2) {
        this.mObservable.f(i, i2);
    }

    public final void notifyItemRemoved(int i) {
        this.mObservable.f(i, 1);
    }

    public void onAttachedToRecyclerView(@NonNull RecyclerView recyclerView) {
    }

    public abstract void onBindViewHolder(F0 f0, int i);

    public void onBindViewHolder(@NonNull F0 f0, int i, @NonNull List<Object> list) {
        onBindViewHolder(f0, i);
    }

    public abstract F0 onCreateViewHolder(ViewGroup viewGroup, int i);

    public void onDetachedFromRecyclerView(@NonNull RecyclerView recyclerView) {
    }

    public boolean onFailedToRecycleView(@NonNull F0 f0) {
        return false;
    }

    public void onViewAttachedToWindow(@NonNull F0 f0) {
    }

    public void onViewDetachedFromWindow(@NonNull F0 f0) {
    }

    public void onViewRecycled(@NonNull F0 f0) {
    }

    public void registerAdapterDataObserver(@NonNull AbstractC1365f0 abstractC1365f0) {
        this.mObservable.registerObserver(abstractC1365f0);
    }

    public void setHasStableIds(boolean z) {
        if (hasObservers()) {
            throw new IllegalStateException("Cannot change whether this adapter has stable IDs while the adapter has registered observers.");
        }
        this.mHasStableIds = z;
    }

    public void setStateRestorationPolicy(@NonNull EnumC1359c0 enumC1359c0) {
        this.mStateRestorationPolicy = enumC1359c0;
        this.mObservable.g();
    }

    public void unregisterAdapterDataObserver(@NonNull AbstractC1365f0 abstractC1365f0) {
        this.mObservable.unregisterObserver(abstractC1365f0);
    }

    public final void notifyItemChanged(int i, Object obj) {
        this.mObservable.d(i, 1, obj);
    }

    public final void notifyItemRangeChanged(int i, int i2, Object obj) {
        this.mObservable.d(i, i2, obj);
    }
}
