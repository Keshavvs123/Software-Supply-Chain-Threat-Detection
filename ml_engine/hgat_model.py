import torch
import torch.nn as nn
import torch.nn.functional as F
try:
    from torch_geometric.nn import GATConv
except ImportError:
    class GATConv(nn.Module):
        """
        Pure PyTorch fallback GATConv when torch_geometric is not installed.
        Provides multi-head attention and attention weight extraction.
        """
        def __init__(self, in_channels, out_channels, heads=1, concat=True, dropout=0.0):
            super(GATConv, self).__init__()
            self.in_channels = in_channels
            self.out_channels = out_channels
            self.heads = heads
            self.concat = concat
            self.dropout = dropout
            self.lin = nn.Linear(in_channels, heads * out_channels, bias=False)
            self.att = nn.Parameter(torch.Tensor(1, heads, 2 * out_channels))
            nn.init.xavier_uniform_(self.lin.weight)
            nn.init.xavier_uniform_(self.att)

        def forward(self, x, edge_index, return_attention_weights=False):
            N = x.size(0)
            h = self.lin(x).view(N, self.heads, self.out_channels)
            if edge_index is None or edge_index.size(1) == 0:
                out = h.view(N, -1) if self.concat else h.mean(dim=1)
                if return_attention_weights:
                    return out, (edge_index, torch.empty((0, self.heads), device=x.device))
                return out

            src, dst = edge_index[0], edge_index[1]
            h_src = h[src]
            h_dst = h[dst]
            cat = torch.cat([h_src, h_dst], dim=-1)
            alpha = F.leaky_relu((cat * self.att).sum(dim=-1), negative_slope=0.2)
            alpha = torch.softmax(alpha, dim=0)

            out = torch.zeros(N, self.heads, self.out_channels, device=x.device)
            out.index_add_(0, dst, h_src * alpha.unsqueeze(-1))
            if self.concat:
                out = out.view(N, self.heads * self.out_channels)
            else:
                out = out.mean(dim=1)
            if return_attention_weights:
                return out, (edge_index, alpha)
            return out

class HGATModel(nn.Module):
    def __init__(self, in_channels=13, hidden_channels=64, out_channels=1, heads=4):
        super(HGATModel, self).__init__()
        # We use a multi-head Graph Attention Network (GAT)
        self.conv1 = GATConv(in_channels, hidden_channels, heads=heads, concat=True, dropout=0.1)
        self.conv2 = GATConv(hidden_channels * heads, hidden_channels, heads=1, concat=False, dropout=0.1)
        
        # Dense classification layers
        self.fc1 = nn.Linear(hidden_channels, hidden_channels // 2)
        self.fc2 = nn.Linear(hidden_channels // 2, out_channels)
        
        # Weight initialization
        self._init_weights()

    def _init_weights(self):
        for m in self.modules():
            if isinstance(m, nn.Linear):
                nn.init.xavier_uniform_(m.weight)
                if m.bias is not None:
                    nn.init.constant_(m.bias, 0.0)

    def forward(self, x, edge_index, return_attention=False):
        """
        x: Node feature matrix of shape (num_nodes, 13)
        edge_index: Graph adjacency of shape (2, num_edges)
        """
        # First GAT layer
        h = self.conv1(x, edge_index)
        h = F.elu(h)
        h = F.dropout(h, p=0.1, training=self.training)
        
        # Second GAT layer — capture attention here (closest to the decision)
        if return_attention:
            # GATConv returns (out, (edge_index, att_weights))
            h, (att_edge_index, att_weights) = self.conv2(h, edge_index, return_attention_weights=True)
        else:
            h = self.conv2(h, edge_index)
        h = F.elu(h)
        
        # Fully connected predictor
        out = F.relu(self.fc1(h))
        out = self.fc2(out)
        
        # Sigmoid probability
        prob = torch.sigmoid(out)
        
        if return_attention:
            return prob, att_edge_index, att_weights
        return prob
