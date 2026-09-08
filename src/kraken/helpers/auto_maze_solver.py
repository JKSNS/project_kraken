#!/usr/bin/env python3
"""Solve maze challenges from PyTorch .pt files or text maze representations.

Handles:
  - PyTorch maze.pt files with maze encoded in weight matrix
  - Text-based maze grids (0=path, 1=wall, 2=start, 3=end)
"""
import sys
import argparse
import hashlib
from collections import deque


def load_pytorch_maze(path: str):
    """Load maze from PyTorch .pt file."""
    try:
        import torch
        import numpy as np
    except ImportError:
        print("[-] PyTorch not installed")
        return None

    # Define stub class for deserialization
    class Maze:
        def __init__(self, *args, **kwargs):
            self.__dict__.update(kwargs)

    import __main__
    __main__.Maze = Maze

    try:
        data = torch.load(path, map_location="cpu", weights_only=False)
    except Exception as e:
        print(f"[-] Failed to load {path}: {e}")
        return None

    # Try to find the maze matrix in modules
    modules = getattr(data, "_modules", {})
    for name, module in modules.items():
        if hasattr(module, "weight"):
            weight = module.weight.detach().numpy()
            if weight.shape[0] >= 5 and weight.shape[1] >= 5:
                return np.round(weight).astype(int)

    # Try state_dict
    if hasattr(data, "state_dict"):
        sd = data.state_dict()
        for key, val in sd.items():
            if "weight" in key:
                arr = val.numpy()
                if arr.shape[0] >= 5 and arr.shape[1] >= 5:
                    return np.round(arr).astype(int)

    return None


def solve_maze(maze, directions="WASD"):
    """BFS shortest path through maze. Returns (path_string, start, end)."""
    rows, cols = maze.shape

    start = end = None
    for y in range(rows):
        for x in range(cols):
            if maze[y][x] == 2:
                start = (y, x)
            elif maze[y][x] == 3:
                end = (y, x)

    if not start or not end:
        return None, start, end

    # WASD: W=up, A=left, S=down, D=right
    W, A, S, D = directions
    moves = {W: (-1, 0), S: (1, 0), A: (0, -1), D: (0, 1)}

    queue = deque([(start, "")])
    visited = {start}

    while queue:
        (y, x), path = queue.popleft()
        if (y, x) == end:
            return path, start, end
        for direction, (dy, dx) in moves.items():
            ny, nx = y + dy, x + dx
            if 0 <= ny < rows and 0 <= nx < cols and (ny, nx) not in visited and maze[ny][nx] != 1:
                visited.add((ny, nx))
                queue.append(((ny, nx), path + direction))

    return None, start, end


def main():
    parser = argparse.ArgumentParser(description="Kraken Maze Solver")
    parser.add_argument("maze_file", help="Path to maze file (.pt or .txt)")
    parser.add_argument("--md5", action="store_true", help="Output MD5 of path as flag")
    args = parser.parse_args()

    path = args.maze_file
    print(f"[*] Loading maze: {path}")

    maze = None
    if path.endswith(".pt"):
        maze = load_pytorch_maze(path)
    else:
        # Try text-based maze
        try:
            import numpy as np
            with open(path) as f:
                lines = f.read().strip().splitlines()
            maze = np.array([[int(c) for c in line.strip()] for line in lines if line.strip()])
        except Exception:
            pass

    if maze is None:
        print("[-] Could not load maze")
        sys.exit(1)

    print(f"[*] Maze size: {maze.shape[0]}x{maze.shape[1]}")

    solution, start, end = solve_maze(maze)
    if solution is None:
        print("[-] No path found")
        sys.exit(1)

    print(f"[*] Start: {start}, End: {end}")
    print(f"[*] Path length: {len(solution)}")
    print(f"[+] MAZE_SOLVER SUCCESS")
    print(f"[+] EXTRACTED PATH: {solution}")

    if args.md5:
        md5 = hashlib.md5(solution.encode()).hexdigest()
        print(f"[+] EXTRACTED FLAG: flag{{{md5}}}")
    else:
        print(f"[+] EXTRACTED FLAG: {solution}")


if __name__ == "__main__":
    main()
