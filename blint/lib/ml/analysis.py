import safetensors.torch
import numpy as np


def analyze_safetensors(file_path):
    """Analyze SafeTensors with actual weight data"""
    tensors = safetensors.torch.load_file(file_path)

    all_weights = []
    weight_stats = []

    for name, tensor in tensors.items():
        # Convert to numpy for analysis
        if hasattr(tensor, 'detach'):  # PyTorch tensor
            tensor_np = tensor.detach().cpu().numpy()
        else:
            tensor_np = np.array(tensor)

        # Flatten for overall statistics
        flattened = tensor_np.flatten()
        all_weights.extend(flattened.tolist())

        # Individual tensor stats
        weight_stats.append({
            'name': name,
            'shape': tensor_np.shape,
            'dtype': str(tensor_np.dtype),
            'size': tensor_np.size,
            'mean': float(np.mean(tensor_np)),
            'std': float(np.std(tensor_np)),
            'min': float(np.min(tensor_np)),
            'max': float(np.max(tensor_np)),
            'median': float(np.median(tensor_np)),
            'sparsity': float(np.sum(tensor_np == 0) / tensor_np.size),
            'percentiles': {
                '1%': float(np.percentile(tensor_np, 1)),
                '5%': float(np.percentile(tensor_np, 5)),
                '25%': float(np.percentile(tensor_np, 25)),
                '75%': float(np.percentile(tensor_np, 75)),
                '95%': float(np.percentile(tensor_np, 95)),
                '99%': float(np.percentile(tensor_np, 99)),
            }
        })

    # Overall statistics
    all_weights_np = np.array(all_weights)
    overall_stats = {
        'total_parameters': len(all_weights),
        'global_mean': float(np.mean(all_weights_np)),
        'global_std': float(np.std(all_weights_np)),
        'global_min': float(np.min(all_weights_np)),
        'global_max': float(np.max(all_weights_np)),
        'global_median': float(np.median(all_weights_np)),
        'global_sparsity': float(np.sum(all_weights_np == 0) / len(all_weights_np)),
    }

    return {
        'overall': overall_stats,
        'per_tensor': weight_stats,
        'all_weights': all_weights_np
    }
